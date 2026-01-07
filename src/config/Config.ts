import { z } from 'zod';
import { join } from 'path';

/**
 * Configuration schema with validation
 */
const configSchema = z.object({
  // Server configuration
  port: z.number().int().min(1).max(65535).default(3000),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),

  // Backend target configuration
  targetHost: z.string().default('localhost'),
  targetPort: z.number().int().min(1).max(65535).default(4000),

  // Redis configuration
  redisHost: z.string().default('localhost'),
  redisPort: z.number().int().min(1).max(65535).default(6379),

  // Rate limiting configuration
  rateLimitWindowMs: z.number().int().min(1000).default(60000), // 1 minute
  rateLimitMaxRequests: z.number().int().min(1).default(100),
  rateLimitFailClosedLimit: z.number().int().min(1).default(10),

  // JWT configuration
  jwtPublicKeyPath: z.string().default(join(process.cwd(), 'keys', 'public.pem')),
  jwtIssuer: z.string().optional(),
  jwtAudience: z.string().optional(),

  // Logging configuration
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
});

type Config = z.infer<typeof configSchema>;

/**
 * Load and validate configuration from environment variables
 */
export function loadConfig(): Config {
  const rawConfig = {
    port: process.env.PORT ? parseInt(process.env.PORT, 10) : undefined,
    nodeEnv: process.env.NODE_ENV,
    targetHost: process.env.TARGET_HOST,
    targetPort: process.env.TARGET_PORT ? parseInt(process.env.TARGET_PORT, 10) : undefined,
    redisHost: process.env.REDIS_HOST,
    redisPort: process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT, 10) : undefined,
    rateLimitWindowMs: process.env.RATE_LIMIT_WINDOW_MS
      ? parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10)
      : undefined,
    rateLimitMaxRequests: process.env.RATE_LIMIT_MAX_REQUESTS
      ? parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10)
      : undefined,
    rateLimitFailClosedLimit: process.env.RATE_LIMIT_FAIL_CLOSED_LIMIT
      ? parseInt(process.env.RATE_LIMIT_FAIL_CLOSED_LIMIT, 10)
      : undefined,
    jwtPublicKeyPath: process.env.JWT_PUBLIC_KEY_PATH,
    jwtIssuer: process.env.JWT_ISSUER,
    jwtAudience: process.env.JWT_AUDIENCE,
    logLevel: process.env.LOG_LEVEL,
  };

  try {
    const config = configSchema.parse(rawConfig);
    return config;
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('Configuration validation failed:');
      console.error(error.issues);
      throw new Error('Invalid configuration');
    }
    throw error;
  }
}

export type { Config };
