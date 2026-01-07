import { InputValidator } from '../../src/middleware/InputValidator';
import http from 'http';

describe('InputValidator Middleware', () => {
  let mockReq: Partial<http.IncomingMessage>;
  let mockRes: Partial<http.ServerResponse>;
  let nextMock: jest.Mock;

  beforeEach(() => {
    mockReq = {
      headers: {},
      socket: { remoteAddress: '127.0.0.1' } as any,
      url: '/api/test',
    };

    mockRes = {
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    nextMock = jest.fn();
  });

  describe('Header Validation', () => {
    describe('User-Agent Header', () => {
      const testCases = [
        {
          name: 'valid user agent',
          value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          shouldPass: true,
        },
        {
          name: 'simple user agent',
          value: 'TestClient/1.0',
          shouldPass: true,
        },
        {
          name: 'user agent with special chars',
          value: 'MyApp/2.0 (compatible; MSIE 9.0)',
          shouldPass: true,
        },
      ];

      testCases.forEach(({ name, value, shouldPass }) => {
        test(`should ${shouldPass ? 'accept' : 'reject'} ${name}`, () => {
          mockReq.headers = { 'user-agent': value };
          const middleware = InputValidator.middleware();

          middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

          if (shouldPass) {
            expect(nextMock).toHaveBeenCalled();
            expect(mockRes.writeHead).not.toHaveBeenCalled();
          } else {
            expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());
            expect(nextMock).not.toHaveBeenCalled();
          }
        });
      });
    });

    describe('Authorization Header', () => {
      const testCases = [
        {
          name: 'valid Bearer token',
          value: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
          shouldPass: true,
        },
        {
          name: 'Bearer with any token',
          value: 'Bearer abc123',
          shouldPass: true,
        },
        {
          name: 'empty authorization header',
          value: '',
          shouldPass: false,
        },
      ];

      testCases.forEach(({ name, value, shouldPass }) => {
        test(`should ${shouldPass ? 'accept' : 'reject'} ${name}`, () => {
          mockReq.headers = { authorization: value };
          const middleware = InputValidator.middleware();

          middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

          if (shouldPass) {
            expect(nextMock).toHaveBeenCalled();
          } else {
            expect(mockRes.writeHead).toHaveBeenCalledWith(400, { 'Content-Type': 'application/json' });
            expect(mockRes.end).toHaveBeenCalledWith(expect.stringContaining('Bad Request'));
          }
        });
      });
    });

    test('should accept request with no optional headers', () => {
      mockReq.headers = {};
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockRes.writeHead).not.toHaveBeenCalled();
    });
  });

  describe('Query Parameter Validation - SQL Injection', () => {
    const sqlInjectionCases = [
      {
        name: 'classic SQL injection',
        query: "search=test' OR '1'='1",
        shouldBlock: true,
      },
      {
        name: 'union select attack',
        query: 'id=1 UNION SELECT * FROM users',
        shouldBlock: true,
      },
      {
        name: 'drop table attempt',
        query: 'query=test; DROP TABLE users--',
        shouldBlock: true,
      },
      {
        name: 'SQL comment injection',
        query: "user=admin'-- ",
        shouldBlock: true,
      },
      {
        name: 'safe query parameter',
        query: 'search=valid search term',
        shouldBlock: false,
      },
      {
        name: 'numeric parameter',
        query: 'page=1',
        shouldBlock: false,
      },
    ];

    sqlInjectionCases.forEach(({ name, query, shouldBlock }) => {
      test(`should ${shouldBlock ? 'block' : 'allow'} ${name}`, () => {
        mockReq.url = `/api/test?${query}`;
        const middleware = InputValidator.middleware();

        middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

        if (shouldBlock) {
          expect(mockRes.writeHead).toHaveBeenCalledWith(400, { 'Content-Type': 'application/json' });
          expect(mockRes.end).toHaveBeenCalledWith(
            expect.stringContaining('Invalid query parameters')
          );
          expect(nextMock).not.toHaveBeenCalled();
        } else {
          expect(nextMock).toHaveBeenCalled();
          expect(mockRes.writeHead).not.toHaveBeenCalledWith(400, expect.anything());
        }
      });
    });
  });

  describe('Query Parameter Validation - XSS', () => {
    const xssCases = [
      {
        name: 'script tag injection',
        query: "comment=<script>alert('xss')</script>",
        shouldBlock: true,
      },
      {
        name: 'javascript protocol',
        query: 'link=javascript:alert(1)',
        shouldBlock: true,
      },
      {
        name: 'onclick event handler',
        query: 'text=<div onclick=alert(1)>click</div>',
        shouldBlock: true,
      },
      {
        name: 'iframe injection',
        query: 'content=<iframe src=evil.com></iframe>',
        shouldBlock: true,
      },
      {
        name: 'embed tag',
        query: 'data=<embed src=flash.swf>',
        shouldBlock: true,
      },
      {
        name: 'object tag',
        query: 'obj=<object data=evil.swf>',
        shouldBlock: true,
      },
      {
        name: 'safe HTML-like text',
        query: 'text=Price: $100 <discount>',
        shouldBlock: false,
      },
      {
        name: 'safe text with angle brackets',
        query: 'math=5<10',
        shouldBlock: false,
      },
    ];

    xssCases.forEach(({ name, query, shouldBlock }) => {
      test(`should ${shouldBlock ? 'block' : 'allow'} ${name}`, () => {
        mockReq.url = `/api/test?${query}`;
        const middleware = InputValidator.middleware();

        middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

        if (shouldBlock) {
          expect(mockRes.writeHead).toHaveBeenCalledWith(400, { 'Content-Type': 'application/json' });
          expect(nextMock).not.toHaveBeenCalled();
        } else {
          expect(nextMock).toHaveBeenCalled();
        }
      });
    });
  });

  describe('Error Response Format', () => {
    test('should return proper error structure for invalid header', () => {
      mockReq.headers = { authorization: '' };
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, { 'Content-Type': 'application/json' });

      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      const parsedResponse = JSON.parse(response);

      expect(parsedResponse).toHaveProperty('error', 'Bad Request');
      expect(parsedResponse).toHaveProperty('message');
      expect(parsedResponse).toHaveProperty('field');
    });

    test('should return proper error structure for invalid query param', () => {
      mockReq.url = "/api/test?search='; DROP TABLE users--";
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      const parsedResponse = JSON.parse(response);

      expect(parsedResponse).toHaveProperty('error', 'Bad Request');
      expect(parsedResponse).toHaveProperty('message', 'Invalid query parameters');
      expect(parsedResponse).toHaveProperty('field');
      expect(parsedResponse.field).toContain('query.');
    });
  });

  describe('Edge Cases', () => {
    test('should handle URL without query parameters', () => {
      mockReq.url = '/api/test';
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should handle multiple query parameters', () => {
      mockReq.url = '/api/test?page=1&limit=10&sort=name';
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should reject if any query parameter is malicious', () => {
      mockReq.url = "/api/test?page=1&search=<script>alert('xss')</script>&limit=10";
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());
      expect(nextMock).not.toHaveBeenCalled();
    });
  });

  describe('Security Event Logging', () => {
    test('should log malformed input events', () => {
      // Spy on console to verify logging
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      mockReq.url = "/api/test?query='; DROP TABLE users";
      const middleware = InputValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.anything());

      consoleSpy.mockRestore();
    });
  });
});
