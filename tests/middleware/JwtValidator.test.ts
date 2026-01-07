import { JwtValidator, JwtConfig } from '../../src/middleware/JwtValidator';
import http from 'http';
import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

describe('JwtValidator Middleware', () => {
  let publicKeyPath: string;
  let privateKey: string;
  let jwtValidator: JwtValidator;
  let mockReq: Partial<http.IncomingMessage>;
  let mockRes: Partial<http.ServerResponse>;
  let nextMock: jest.Mock;

  beforeAll(() => {
    // Generate test RSA keys
    const { publicKey, privateKey: privKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    privateKey = privKey;

    // Create temp directory for test keys
    const testKeysDir = join(process.cwd(), 'tests', 'temp-keys');
    if (!existsSync(testKeysDir)) {
      mkdirSync(testKeysDir, { recursive: true });
    }

    publicKeyPath = join(testKeysDir, 'test-public.pem');
    writeFileSync(publicKeyPath, publicKey);
  });

  afterAll(() => {
    // Cleanup
    if (existsSync(publicKeyPath)) {
      unlinkSync(publicKeyPath);
    }
  });

  beforeEach(() => {
    const config: JwtConfig = {
      publicKeyPath,
    };

    jwtValidator = new JwtValidator(config);

    mockReq = {
      headers: {},
      socket: { remoteAddress: '127.0.0.1' } as any,
      url: '/api/protected',
    };

    mockRes = {
      setHeader: jest.fn(),
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    nextMock = jest.fn();
  });

  describe('Token Extraction', () => {
    test('should extract valid Bearer token', () => {
      const token = jwt.sign({ sub: 'user123' }, privateKey, { algorithm: 'RS256' });
      mockReq.headers = { authorization: `Bearer ${token}` };

      const middleware = jwtValidator.middleware();
      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should reject missing Authorization header', () => {
      mockReq.headers = {};
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, { 'Content-Type': 'application/json' });
      expect(mockRes.end).toHaveBeenCalledWith(
        expect.stringContaining('Authorization token required')
      );
      expect(nextMock).not.toHaveBeenCalled();
    });

    test('should reject malformed Authorization header', () => {
      mockReq.headers = { authorization: 'NotBearer token' };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(nextMock).not.toHaveBeenCalled();
    });

    test('should reject Authorization header without token', () => {
      mockReq.headers = { authorization: 'Bearer' };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
    });
  });

  describe('Token Validation', () => {
    test('should validate valid RS256 token', () => {
      const token = jwt.sign(
        { sub: 'user123', name: 'Test User' },
        privateKey,
        { algorithm: 'RS256', expiresIn: '1h' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
      expect(mockRes.writeHead).not.toHaveBeenCalledWith(401, expect.anything());
    });

    test('should reject token with invalid signature', () => {
      // Create token with different key
      const { privateKey: wrongKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const token = jwt.sign({ sub: 'user123' }, wrongKey, { algorithm: 'RS256' });
      mockReq.headers = { authorization: `Bearer ${token}` };

      const middleware = jwtValidator.middleware();
      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(mockRes.end).toHaveBeenCalledWith(
        expect.stringContaining('Invalid authentication token')
      );
      expect(nextMock).not.toHaveBeenCalled();
    });

    test('should reject malformed JWT', () => {
      mockReq.headers = { authorization: 'Bearer not.a.valid.jwt' };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(nextMock).not.toHaveBeenCalled();
    });
  });

  describe('Token Expiration - Edge Cases', () => {
    test('should accept token that expires in future', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now + 3600 }, // Expires in 1 hour
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should reject token expired by exactly 1 second', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now - 1 }, // Expired 1 second ago
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(mockRes.end).toHaveBeenCalledWith(
        expect.stringContaining('Token has expired')
      );
      expect(nextMock).not.toHaveBeenCalled();
    });

    test('should accept token expiring in exactly 1 second', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now + 1 }, // Expires in 1 second
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should reject token expired by 1 hour', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now - 3600 }, // Expired 1 hour ago
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(mockRes.end).toHaveBeenCalledWith(expect.stringContaining('expired'));
    });

    // Critical boundary test
    test('should handle token at exact expiration moment', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now }, // Expires now
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      // Should be expired (exp is not inclusive)
      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
    });
  });

  describe('User Identity Extraction', () => {
    test('should attach user ID to request headers', () => {
      const token = jwt.sign({ sub: 'user123' }, privateKey, { algorithm: 'RS256' });
      mockReq.headers = { authorization: `Bearer ${token}` };

      const middleware = jwtValidator.middleware();
      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith('X-User-Id', 'user123');
      expect((mockReq.headers as any)['x-user-id']).toBe('user123');
    });

    test('should attach issuer if present', () => {
      const token = jwt.sign(
        { sub: 'user123', iss: 'shield-ts' },
        privateKey,
        { algorithm: 'RS256' }
      );
      mockReq.headers = { authorization: `Bearer ${token}` };

      const middleware = jwtValidator.middleware();
      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith('X-User-Issuer', 'shield-ts');
    });

    test('should extract all standard claims', () => {
      const payload = {
        sub: 'user456',
        name: 'John Doe',
        email: 'john@example.com',
        iat: Math.floor(Date.now() / 1000),
      };

      const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
      mockReq.headers = { authorization: `Bearer ${token}` };

      const middleware = jwtValidator.middleware();
      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.setHeader).toHaveBeenCalledWith('X-User-Id', 'user456');
      expect(nextMock).toHaveBeenCalled();
    });
  });

  describe('Issuer and Audience Validation', () => {
    test('should validate issuer when configured', () => {
      const config: JwtConfig = {
        publicKeyPath,
        issuer: 'test-issuer',
      };

      const validatorWithIssuer = new JwtValidator(config);

      // Token with correct issuer
      const validToken = jwt.sign(
        { sub: 'user123' },
        privateKey,
        { algorithm: 'RS256', issuer: 'test-issuer' }
      );

      mockReq.headers = { authorization: `Bearer ${validToken}` };
      const middleware = validatorWithIssuer.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(nextMock).toHaveBeenCalled();
    });

    test('should reject token with wrong issuer', () => {
      const config: JwtConfig = {
        publicKeyPath,
        issuer: 'expected-issuer',
      };

      const validatorWithIssuer = new JwtValidator(config);

      const invalidToken = jwt.sign(
        { sub: 'user123' },
        privateKey,
        { algorithm: 'RS256', issuer: 'wrong-issuer' }
      );

      mockReq.headers = { authorization: `Bearer ${invalidToken}` };
      const middleware = validatorWithIssuer.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      expect(mockRes.writeHead).toHaveBeenCalledWith(401, expect.anything());
      expect(nextMock).not.toHaveBeenCalled();
    });
  });

  describe('Error Response Format', () => {
    test('should return proper error for expired token', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: 'user123', exp: now - 10 },
        privateKey,
        { algorithm: 'RS256' }
      );

      mockReq.headers = { authorization: `Bearer ${token}` };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      const parsedResponse = JSON.parse(response);

      expect(parsedResponse).toHaveProperty('error', 'Unauthorized');
      expect(parsedResponse).toHaveProperty('message', 'Token has expired');
    });

    test('should return proper error for invalid signature', () => {
      mockReq.headers = { authorization: 'Bearer invalid.token.signature' };
      const middleware = jwtValidator.middleware();

      middleware(mockReq as http.IncomingMessage, mockRes as http.ServerResponse, nextMock);

      const response = (mockRes.end as jest.Mock).mock.calls[0][0];
      const parsedResponse = JSON.parse(response);

      expect(parsedResponse).toHaveProperty('error', 'Unauthorized');
      expect(parsedResponse).toHaveProperty('message', 'Invalid authentication token');
    });
  });
});
