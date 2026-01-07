import http from 'http';
import { generateKeyPairSync } from 'crypto';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import jwt from 'jsonwebtoken';
import { RateLimiter } from '../../src/middleware/RateLimiter';
import { InputValidator } from '../../src/middleware/InputValidator';
import { JwtValidator } from '../../src/middleware/JwtValidator';

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

describe('Full Security Pipeline Integration', () => {
  let publicKeyPath: string;
  let privateKey: string;
  let rateLimiter: RateLimiter;
  let jwtValidator: JwtValidator;

  beforeAll(() => {
    // Generate test RSA keys
    const { publicKey, privateKey: privKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    privateKey = privKey;

    const testKeysDir = join(process.cwd(), 'tests', 'temp-keys');
    if (!existsSync(testKeysDir)) {
      mkdirSync(testKeysDir, { recursive: true });
    }

    publicKeyPath = join(testKeysDir, 'integration-public.pem');
    writeFileSync(publicKeyPath, publicKey);
  });

  afterAll(() => {
    if (existsSync(publicKeyPath)) {
      unlinkSync(publicKeyPath);
    }
  });

  beforeEach(() => {
    rateLimiter = new RateLimiter({
      windowMs: 60000,
      maxRequests: 100,
      redisHost: 'localhost',
      redisPort: 6379,
      failClosedLimit: 5,
    });

    jwtValidator = new JwtValidator({ publicKeyPath });
  });

  afterEach(async () => {
    await rateLimiter.close();
  });

  const executeMiddlewareChain = async (
    middlewares: Array<
      (req: http.IncomingMessage, res: http.ServerResponse, next: () => void) => void | Promise<void>
    >,
    req: Partial<http.IncomingMessage>,
    res: Partial<http.ServerResponse>
  ): Promise<boolean> => {
    let index = 0;
    let reachedEnd = false;

    const next = (): void => {
      if (index >= middlewares.length) {
        reachedEnd = true;
        return;
      }

      const middleware = middlewares[index++];
      const result = middleware(req as http.IncomingMessage, res as http.ServerResponse, next);

      if (result instanceof Promise) {
        result.catch(() => {
          // Handle promise rejection
        });
      }
    };

    return new Promise((resolve) => {
      next();
      // Wait a bit for async operations
      setTimeout(() => resolve(reachedEnd), 100);
    });
  };

  describe('Happy Path - Valid Request', () => {
    test('should pass through all middlewares with valid request', async () => {
      const token = jwt.sign(
        { sub: 'user123', name: 'Test User' },
        privateKey,
        { algorithm: 'RS256', expiresIn: '1h' }
      );

      const mockReq: Partial<http.IncomingMessage> = {
        headers: {
          authorization: `Bearer ${token}`,
          'user-agent': 'TestClient/1.0',
        },
        socket: { remoteAddress: '127.0.0.1' } as any,
        url: '/api/test?page=1',
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      const reachedEnd = await executeMiddlewareChain(middlewares, mockReq, mockRes);

      expect(reachedEnd).toBe(true);
      expect(mockRes.writeHead).not.toHaveBeenCalled();
    });
  });

  describe('Security Rejection Scenarios', () => {
    test('should block at rate limiter when limit exceeded', async () => {
      const token = jwt.sign({ sub: 'user123' }, privateKey, { algorithm: 'RS256' });

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${token}` },
        socket: { remoteAddress: '127.0.0.1' } as any,
        url: '/api/test',
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      // Exhaust rate limit (5 requests in fail-closed mode)
      for (let i = 0; i < 5; i++) {
        const mockRes: Partial<http.ServerResponse> = {
          setHeader: jest.fn(),
          writeHead: jest.fn(),
          end: jest.fn(),
        };
        await executeMiddlewareChain(middlewares, mockReq, mockRes);
      }

      // Next request should be blocked
      const finalRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      await executeMiddlewareChain(middlewares, mockReq, finalRes);

      expect(finalRes.writeHead).toHaveBeenCalledWith(429, expect.anything());
    });

    test('should block at input validator for malicious query', async () => {
      const token = jwt.sign({ sub: 'user123' }, privateKey, { algorithm: 'RS256' });

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${token}` },
        socket: { remoteAddress: '192.168.1.1' } as any,
        url: "/api/test?query=' OR '1'='1",
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      const reachedEnd = await executeMiddlewareChain(middlewares, mockReq, mockRes);

      expect(reachedEnd).toBe(false);
      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());
    });

    test('should block at JWT validator for invalid token', async () => {
      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: 'Bearer invalid.token.here' },
        socket: { remoteAddress: '192.168.1.2' } as any,
        url: '/api/test',
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      const reachedEnd = await executeMiddlewareChain(middlewares, mockReq, mockRes);

      expect(reachedEnd).toBe(false);
      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
    });

    test('should block at JWT validator for expired token', async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = jwt.sign(
        { sub: 'user123', exp: now - 10 },
        privateKey,
        { algorithm: 'RS256' }
      );

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${expiredToken}` },
        socket: { remoteAddress: '192.168.1.3' } as any,
        url: '/api/test',
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      const reachedEnd = await executeMiddlewareChain(middlewares, mockReq, mockRes);

      expect(reachedEnd).toBe(false);
      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      expect(response).toContain('expired');
    });
  });

  describe('Middleware Ordering', () => {
    test('should execute middlewares in correct order', async () => {
      const executionOrder: string[] = [];

      const tracker1 = (_req: http.IncomingMessage, _res: http.ServerResponse, next: () => void) => {
        executionOrder.push('middleware1');
        next();
      };

      const tracker2 = (_req: http.IncomingMessage, _res: http.ServerResponse, next: () => void) => {
        executionOrder.push('middleware2');
        next();
      };

      const tracker3 = (_req: http.IncomingMessage, _res: http.ServerResponse, next: () => void) => {
        executionOrder.push('middleware3');
        next();
      };

      const mockReq: Partial<http.IncomingMessage> = {
        headers: {},
        socket: { remoteAddress: '127.0.0.1' } as any,
        url: '/test',
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      await executeMiddlewareChain([tracker1, tracker2, tracker3], mockReq, mockRes);

      expect(executionOrder).toEqual(['middleware1', 'middleware2', 'middleware3']);
    });

    test('should stop execution when middleware blocks request', async () => {
      const executionOrder: string[] = [];

      const pass = (_req: http.IncomingMessage, _res: http.ServerResponse, next: () => void) => {
        executionOrder.push('pass');
        next();
      };

      const block = (_req: http.IncomingMessage, res: http.ServerResponse, _next: () => void) => {
        executionOrder.push('block');
        res.writeHead(403, {});
        res.end();
      };

      const shouldNotRun = (_req: http.IncomingMessage, _res: http.ServerResponse, next: () => void) => {
        executionOrder.push('shouldNotRun');
        next();
      };

      const mockReq: Partial<http.IncomingMessage> = {
        headers: {},
        socket: { remoteAddress: '127.0.0.1' } as any,
        url: '/test',
      };

      const mockRes: Partial<http.ServerResponse> = {
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      await executeMiddlewareChain([pass, block, shouldNotRun], mockReq, mockRes);

      expect(executionOrder).toEqual(['pass', 'block']);
      expect(executionOrder).not.toContain('shouldNotRun');
    });
  });

  describe('User Identity Propagation', () => {
    test('should propagate user ID through pipeline for rate limiting', async () => {
      const token = jwt.sign({ sub: 'user456' }, privateKey, { algorithm: 'RS256' });

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${token}` },
        socket: { remoteAddress: '127.0.0.1' } as any,
        url: '/api/test',
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      await executeMiddlewareChain(middlewares, mockReq, mockRes);

      // After JWT validation, user ID should be in headers
      expect((mockReq.headers as any)['x-user-id']).toBe('user456');
      expect(mockRes.setHeader).toHaveBeenCalledWith('X-User-Id', 'user456');
    });
  });

  describe('Combined Attack Scenarios', () => {
    test('should handle SQL injection attempt with valid JWT', async () => {
      const token = jwt.sign({ sub: 'attacker' }, privateKey, { algorithm: 'RS256' });

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${token}` },
        socket: { remoteAddress: '192.168.1.100' } as any,
        url: "/api/users?id=1; DROP TABLE users--",
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      await executeMiddlewareChain(middlewares, mockReq, mockRes);

      // Should be blocked at input validation, not reach JWT validation
      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());
    });

    test('should handle XSS attempt with valid JWT', async () => {
      const token = jwt.sign({ sub: 'attacker' }, privateKey, { algorithm: 'RS256' });

      const mockReq: Partial<http.IncomingMessage> = {
        headers: { authorization: `Bearer ${token}` },
        socket: { remoteAddress: '192.168.1.101' } as any,
        url: "/api/search?q=<script>alert('xss')</script>",
      };

      const mockRes: Partial<http.ServerResponse> = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      const middlewares = [
        rateLimiter.middleware(),
        InputValidator.middleware(),
        jwtValidator.middleware(),
      ];

      await executeMiddlewareChain(middlewares, mockReq, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());
    });
  });
});
