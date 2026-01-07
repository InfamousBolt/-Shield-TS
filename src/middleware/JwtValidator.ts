import http from 'http';
import jwt from 'jsonwebtoken';
import { readFileSync } from 'fs';
import logger, { logSecurityEvent } from '../logging/Logger';
import { SecurityEventType, AuthFailureEvent } from '../logging/SecurityEvents';

export interface JwtConfig {
  publicKeyPath: string;
  issuer?: string;
  audience?: string;
}

export interface JwtPayload {
  sub: string; // User ID
  iss?: string; // Issuer
  aud?: string; // Audience
  exp?: number; // Expiration time
  iat?: number; // Issued at
  [key: string]: unknown;
}

export class JwtValidator {
  private publicKey: string;
  private config: JwtConfig;

  constructor(config: JwtConfig) {
    this.config = config;

    try {
      // Load public key for RS256 verification
      this.publicKey = readFileSync(config.publicKeyPath, 'utf8');
      logger.info({ keyPath: config.publicKeyPath }, 'JWT public key loaded');
    } catch (error) {
      logger.error({ error, keyPath: config.publicKeyPath }, 'Failed to load JWT public key');
      throw new Error(`Failed to load JWT public key: ${(error as Error).message}`);
    }
  }

  /**
   * Extract JWT from Authorization header
   */
  private extractToken(req: http.IncomingMessage): string | null {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return null;
    }

    // Authorization header format: "Bearer <token>"
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Get client IP for logging
   */
  private getClientIp(req: http.IncomingMessage): string {
    const forwarded = req.headers['x-forwarded-for'] as string;
    return forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress || 'unknown';
  }

  /**
   * Verify JWT signature and claims
   */
  private verifyToken(token: string): JwtPayload {
    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'], // Only allow RS256
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as JwtPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('TOKEN_EXPIRED');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('INVALID_TOKEN');
      } else {
        throw new Error('VERIFICATION_FAILED');
      }
    }
  }

  /**
   * JWT validation middleware
   */
  public middleware() {
    return (
      req: http.IncomingMessage,
      res: http.ServerResponse,
      next: () => void
    ): void => {
      const clientIp = this.getClientIp(req);

      // Extract token from Authorization header
      const token = this.extractToken(req);

      if (!token) {
        logger.warn({ ip: clientIp, url: req.url }, 'Missing authorization token');

        logSecurityEvent({
          type: SecurityEventType.AUTH_FAILURE,
          timestamp: new Date().toISOString(),
          ip: clientIp,
          path: req.url,
          message: 'Authorization header missing or malformed',
          reason: 'MISSING_TOKEN',
        } as AuthFailureEvent);

        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Unauthorized',
            message: 'Authorization token required',
          })
        );
        return;
      }

      try {
        // Verify token signature and claims
        const payload = this.verifyToken(token);

        // Attach user identity to request headers for downstream services
        res.setHeader('X-User-Id', payload.sub);
        if (payload.iss) {
          res.setHeader('X-User-Issuer', payload.iss);
        }

        // Also set on request headers for rate limiter to use
        (req.headers as Record<string, string>)['x-user-id'] = payload.sub;

        logger.debug(
          { userId: payload.sub, url: req.url },
          'JWT validation successful'
        );

        next();
      } catch (error) {
        const errorMessage = (error as Error).message;

        let eventType = SecurityEventType.INVALID_JWT;
        let reason = 'INVALID_TOKEN';

        if (errorMessage === 'TOKEN_EXPIRED') {
          eventType = SecurityEventType.EXPIRED_JWT;
          reason = 'TOKEN_EXPIRED';
        } else if (errorMessage === 'INVALID_TOKEN') {
          eventType = SecurityEventType.INVALID_JWT;
          reason = 'INVALID_SIGNATURE';
        }

        logger.warn(
          { ip: clientIp, url: req.url, reason },
          'JWT validation failed'
        );

        logSecurityEvent({
          type: eventType,
          timestamp: new Date().toISOString(),
          ip: clientIp,
          path: req.url,
          message: `JWT validation failed: ${reason}`,
          reason,
        } as AuthFailureEvent);

        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Unauthorized',
            message: reason === 'TOKEN_EXPIRED'
              ? 'Token has expired'
              : 'Invalid authentication token',
          })
        );
      }
    };
  }
}
