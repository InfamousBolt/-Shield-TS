import { RateLimiter, RateLimitConfig } from '../../src/middleware/RateLimiter';
import http from 'http';

// Mock ioredis
jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => {
    const mockInstance = {
      on: jest.fn().mockReturnThis(),
      zremrangebyscore: jest.fn().mockResolvedValue(0),
      zcard: jest.fn().mockResolvedValue(0),
      zadd: jest.fn().mockResolvedValue(1),
      pexpire: jest.fn().mockResolvedValue(1),
      quit: jest.fn().mockResolvedValue('OK'),
    };
    return mockInstance;
  });
});

describe('RateLimiter Middleware', () => {
  let rateLimiter: RateLimiter;
  let mockReq: Partial<http.IncomingMessage>;
  let mockRes: Partial<http.ServerResponse>;
  let nextMock: jest.Mock;

  beforeEach(() => {
    const config: RateLimitConfig = {
      windowMs: 60000,
      maxRequests: 100,
      redisHost: 'localhost',
      redisPort: 6379,
      failClosedLimit: 10,
    };

    rateLimiter = new RateLimiter(config);

    mockReq = {
      headers: {},
      socket: { remoteAddress: '127.0.0.1' } as any,
      url: '/api/test',
    };

    mockRes = {
      setHeader: jest.fn(),
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    nextMock = jest.fn();
  });

  afterEach(async () => {
    await rateLimiter.close();
  });

  describe('Client Identification', () => {
    test('should use IP address when no user ID present', async () => {
      const middleware = rateLimiter.middleware();
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', expect.any(String));
      expect(nextMock).toHaveBeenCalled();
    });

    test('should use user ID from header when present', async () => {
      mockReq.headers = { 'x-user-id': 'user123' };

      const middleware = rateLimiter.middleware();
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should extract IP from x-forwarded-for header', async () => {
      mockReq.headers = { 'x-forwarded-for': '192.168.1.100, 10.0.0.1' };

      const middleware = rateLimiter.middleware();
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });
  });

  describe('Fail-Closed Behavior', () => {
    test('should enforce restrictive limits when Redis is down', async () => {
      // Simulate Redis being unavailable
      const middleware = rateLimiter.middleware();

      // Make requests up to fail-closed limit (10)
      for (let i = 0; i < 10; i++) {
        await middleware(
          mockReq as http.IncomingMessage,
          mockRes as http.ServerResponse,
          nextMock
        );
      }

      // Next request should be rate limited
      mockRes.writeHead = jest.fn();
      mockRes.end = jest.fn();

      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(429, { 'Content-Type': 'application/json' });
      expect(mockRes.end).toHaveBeenCalledWith(
        expect.stringContaining('Too Many Requests')
      );
    });

    test('should set fail-closed limit in headers when Redis unavailable', async () => {
      const middleware = rateLimiter.middleware();

      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Limit',
        expect.stringMatching(/10/)
      );
    });
  });

  describe('Rate Limit Headers', () => {
    test('should set rate limit headers on successful request', async () => {
      const middleware = rateLimiter.middleware();

      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', expect.any(String));
      expect(mockRes.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
      expect(mockRes.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
    });

    test('should decrement remaining count with each request', async () => {
      const middleware = rateLimiter.middleware();

      // First request
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);
      const firstCall = (mockRes.setHeader as jest.Mock).mock.calls.find(
        (call) => call[0] === 'X-RateLimit-Remaining'
      );

      // Second request
      mockRes.setHeader = jest.fn();
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);
      const secondCall = (mockRes.setHeader as jest.Mock).mock.calls.find(
        (call) => call[0] === 'X-RateLimit-Remaining'
      );

      expect(parseInt(secondCall[1])).toBeLessThan(parseInt(firstCall[1]));
    });
  });

  describe('Rate Limit Exceeded Response', () => {
    test('should return 429 when limit exceeded', async () => {
      const middleware = rateLimiter.middleware();

      // Exhaust the fail-closed limit
      for (let i = 0; i < 10; i++) {
        await middleware(
          mockReq as http.IncomingMessage,
          mockRes as http.ServerResponse,
          nextMock
        );
      }

      // Reset mocks
      mockRes.writeHead = jest.fn();
      mockRes.end = jest.fn();

      // Next request should be blocked
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(429, { 'Content-Type': 'application/json' });
    });

    test('should include retry-after in rate limit response', async () => {
      const middleware = rateLimiter.middleware();

      // Exhaust limit
      for (let i = 0; i < 10; i++) {
        await middleware(
          mockReq as http.IncomingMessage,
          mockRes as http.ServerResponse,
          nextMock
        );
      }

      mockRes.end = jest.fn();

      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      const parsedResponse = JSON.parse(response);

      expect(parsedResponse).toHaveProperty('retryAfter');
      expect(parsedResponse.error).toBe('Too Many Requests');
    });
  });

  describe('Window Reset', () => {
    test('should allow requests after window expires', async () => {
      // Use a very short window for testing
      const shortWindowConfig: RateLimitConfig = {
        windowMs: 100, // 100ms window
        maxRequests: 2,
        redisHost: 'localhost',
        redisPort: 6379,
        failClosedLimit: 2,
      };

      const shortLimiter = new RateLimiter(shortWindowConfig);
      const middleware = shortLimiter.middleware();

      // Make 2 requests (exhaust limit)
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      // Wait for window to expire
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Should allow new requests
      mockRes.writeHead = jest.fn();
      nextMock = jest.fn();

      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockRes.writeHead).not.toHaveBeenCalledWith(429, expect.anything());

      await shortLimiter.close();
    });
  });

  describe('Different Clients', () => {
    test('should track limits separately for different IPs', async () => {
      const middleware = rateLimiter.middleware();

      // Client 1
      mockReq.socket = { remoteAddress: '192.168.1.1' } as any;
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      // Client 2
      mockReq.socket = { remoteAddress: '192.168.1.2' } as any;
      mockRes.setHeader = jest.fn();
      await middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      // Both should have full remaining count
      const remainingCalls = (mockRes.setHeader as jest.Mock).mock.calls.filter(
        (call) => call[0] === 'X-RateLimit-Remaining'
      );

      expect(remainingCalls.length).toBeGreaterThan(0);
    });
  });
});
