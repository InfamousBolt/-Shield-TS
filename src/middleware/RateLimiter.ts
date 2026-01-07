import http from 'http';
import Redis from 'ioredis';
import logger, { logSecurityEvent } from '../logging/Logger';
import { SecurityEventType, RateLimitEvent } from '../logging/SecurityEvents';

export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
  redisHost: string;
  redisPort: number;
  failClosedLimit: number; // Very restrictive limit when Redis is down
}

export class RateLimiter {
  private redis: Redis;
  private config: RateLimitConfig;
  private isRedisHealthy: boolean = true;
  private fallbackStore: Map<string, number[]> = new Map();

  constructor(config: RateLimitConfig) {
    this.config = config;

    // Initialize Redis client
    this.redis = new Redis({
      host: config.redisHost,
      port: config.redisPort,
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      maxRetriesPerRequest: 3,
    });

    // Monitor Redis connection health
    this.redis.on('connect', () => {
      this.isRedisHealthy = true;
      logger.info('Redis connection established for rate limiting');
    });

    this.redis.on('error', (err) => {
      this.isRedisHealthy = false;
      logger.error({ error: err.message }, 'Redis connection error');
      logSecurityEvent({
        type: SecurityEventType.REDIS_CONNECTION_FAILURE,
        timestamp: new Date().toISOString(),
        message: `Redis connection failed: ${err.message}`,
        details: { error: err.message },
      });
    });

    this.redis.on('close', () => {
      this.isRedisHealthy = false;
      logger.warn('Redis connection closed');
    });
  }

  /**
   * Extract client identifier from request (IP address or user ID)
   */
  private getClientIdentifier(req: http.IncomingMessage): string {
    // Try to get user ID from custom header (set by JWT middleware)
    const userId = req.headers['x-user-id'] as string;
    if (userId) {
      return `user:${userId}`;
    }

    // Fall back to IP address
    const forwarded = req.headers['x-forwarded-for'] as string;
    const ip = forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress || 'unknown';
    return `ip:${ip}`;
  }

  /**
   * Check rate limit using Redis sliding window algorithm
   */
  private async checkRateLimitRedis(clientId: string): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }> {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const key = `ratelimit:${clientId}`;

    try {
      // Use Redis sorted set for sliding window
      // Remove old entries outside the window
      await this.redis.zremrangebyscore(key, 0, windowStart);

      // Count requests in current window
      const count = await this.redis.zcard(key);

      if (count >= this.config.maxRequests) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: now + this.config.windowMs,
        };
      }

      // Add current request to the sorted set
      await this.redis.zadd(key, now, `${now}-${Math.random()}`);

      // Set expiry on the key
      await this.redis.pexpire(key, this.config.windowMs);

      return {
        allowed: true,
        remaining: this.config.maxRequests - count - 1,
        resetTime: now + this.config.windowMs,
      };
    } catch (error) {
      // Redis operation failed - trigger fail-closed
      throw error;
    }
  }

  /**
   * Fail-closed rate limiter (in-memory, very restrictive)
   */
  private checkRateLimitFallback(clientId: string): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    // Get or create request timestamps for this client
    let timestamps = this.fallbackStore.get(clientId) || [];

    // Remove old timestamps outside the window
    timestamps = timestamps.filter((ts) => ts > windowStart);

    // Apply fail-closed limit (much more restrictive)
    if (timestamps.length >= this.config.failClosedLimit) {
      this.fallbackStore.set(clientId, timestamps);
      return {
        allowed: false,
        remaining: 0,
        resetTime: now + this.config.windowMs,
      };
    }

    // Add current timestamp
    timestamps.push(now);
    this.fallbackStore.set(clientId, timestamps);

    // Clean up old entries periodically
    if (Math.random() < 0.01) {
      // 1% chance
      this.cleanupFallbackStore();
    }

    return {
      allowed: true,
      remaining: this.config.failClosedLimit - timestamps.length,
      resetTime: now + this.config.windowMs,
    };
  }

  /**
   * Clean up old entries from fallback store
   */
  private cleanupFallbackStore(): void {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    for (const [clientId, timestamps] of this.fallbackStore.entries()) {
      const filtered = timestamps.filter((ts) => ts > windowStart);
      if (filtered.length === 0) {
        this.fallbackStore.delete(clientId);
      } else {
        this.fallbackStore.set(clientId, filtered);
      }
    }
  }

  /**
   * Rate limiting middleware
   */
  public middleware() {
    return async (
      req: http.IncomingMessage,
      res: http.ServerResponse,
      next: () => void
    ): Promise<void> => {
      const clientId = this.getClientIdentifier(req);

      try {
        let result;

        if (this.isRedisHealthy) {
          // Try Redis-based rate limiting
          result = await this.checkRateLimitRedis(clientId);
        } else {
          // Use fail-closed fallback
          result = this.checkRateLimitFallback(clientId);
          logger.warn(
            { clientId, limit: this.config.failClosedLimit },
            'Using fail-closed rate limiting (Redis unavailable)'
          );
        }

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', this.config.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
        res.setHeader('X-RateLimit-Reset', result.resetTime.toString());

        if (!result.allowed) {
          // Rate limit exceeded
          logSecurityEvent({
            type: SecurityEventType.RATE_LIMIT_EXCEEDED,
            timestamp: new Date().toISOString(),
            ip: clientId,
            path: req.url,
            message: `Rate limit exceeded for ${clientId}`,
            limit: this.config.maxRequests,
            window: this.config.windowMs,
            requestCount: this.config.maxRequests,
          } as RateLimitEvent);

          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Too Many Requests',
              message: 'Rate limit exceeded. Please try again later.',
              retryAfter: Math.ceil(this.config.windowMs / 1000),
            })
          );
          return;
        }

        // Rate limit check passed
        next();
      } catch (error) {
        // Redis error - use fail-closed fallback
        logger.error({ error }, 'Rate limiter error, using fail-closed mode');

        const result = this.checkRateLimitFallback(clientId);

        res.setHeader('X-RateLimit-Limit', this.config.failClosedLimit.toString());
        res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
        res.setHeader('X-RateLimit-Reset', result.resetTime.toString());

        if (!result.allowed) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Too Many Requests',
              message: 'Service temporarily restricted. Please try again later.',
              retryAfter: Math.ceil(this.config.windowMs / 1000),
            })
          );
          return;
        }

        next();
      }
    };
  }

  public async close(): Promise<void> {
    await this.redis.quit();
  }
}
