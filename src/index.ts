import http from 'http';
import { loadConfig } from './config/Config';
import logger from './logging/Logger';
import { ProxyServer } from './proxy/ProxyServer';
import { RateLimiter } from './middleware/RateLimiter';
import { InputValidator } from './middleware/InputValidator';
import { JwtValidator } from './middleware/JwtValidator';
import { SecurityHeaders } from './middleware/SecurityHeaders';
import { RequestSizeLimit } from './middleware/RequestSizeLimit';
import { BackendServer } from './mock/BackendServer';
import { existsSync } from 'fs';

type Middleware = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  next: () => void
) => void | Promise<void>;

/**
 * Middleware chain executor
 */
function executeMiddlewareChain(
  middlewares: Middleware[],
  req: http.IncomingMessage,
  res: http.ServerResponse,
  finalHandler: () => void
): void {
  let index = 0;

  const next = (): void => {
    if (index >= middlewares.length) {
      finalHandler();
      return;
    }

    const middleware = middlewares[index++];
    try {
      const result = middleware(req, res, next);
      // Handle async middleware
      if (result instanceof Promise) {
        result.catch((error) => {
          logger.error({ error }, 'Middleware error');
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal Server Error' }));
          }
        });
      }
    } catch (error) {
      logger.error({ error }, 'Middleware error');
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
      }
    }
  };

  next();
}

/**
 * Request correlation ID middleware
 */
function correlationIdMiddleware(): Middleware {
  return (req, res, next) => {
    const correlationId = (req.headers['x-correlation-id'] as string) ||
      `${Date.now()}-${Math.random().toString(36).substring(7)}`;

    res.setHeader('X-Correlation-Id', correlationId);
    (req as any).correlationId = correlationId;

    next();
  };
}

/**
 * Request logging middleware
 */
function requestLoggingMiddleware(): Middleware {
  return (req, res, next) => {
    const start = Date.now();

    logger.info({
      method: req.method,
      url: req.url,
      ip: req.socket.remoteAddress,
    }, 'Incoming request');

    // Log when response finishes
    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info({
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration,
      }, 'Request completed');
    });

    next();
  };
}

/**
 * Health check endpoint middleware
 */
function healthCheckMiddleware(): Middleware {
  return (req, res, next) => {
    if (req.url === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'healthy',
        service: 'shield-ts-gateway',
        timestamp: new Date().toISOString(),
      }));
      return;
    }
    next();
  };
}

/**
 * Main application entry point
 */
async function main(): Promise<void> {
  // Load configuration
  const config = loadConfig();

  logger.info({ config: {
    port: config.port,
    targetHost: config.targetHost,
    targetPort: config.targetPort,
    nodeEnv: config.nodeEnv,
  }}, 'Starting Shield-TS Gateway');

  // Start mock backend server if in development
  let backendServer: BackendServer | undefined;
  if (config.nodeEnv === 'development') {
    backendServer = new BackendServer(config.targetPort);
    backendServer.start();
  }

  // Check if JWT public key exists
  if (!existsSync(config.jwtPublicKeyPath)) {
    logger.warn(
      { keyPath: config.jwtPublicKeyPath },
      'JWT public key not found. JWT authentication will fail. Generate keys using: npm run generate-keys'
    );
  }

  // Initialize components
  const rateLimiter = new RateLimiter({
    windowMs: config.rateLimitWindowMs,
    maxRequests: config.rateLimitMaxRequests,
    redisHost: config.redisHost,
    redisPort: config.redisPort,
    failClosedLimit: config.rateLimitFailClosedLimit,
  });

  const jwtValidator = new JwtValidator({
    publicKeyPath: config.jwtPublicKeyPath,
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
  });

  const proxyServer = new ProxyServer({
    port: config.port,
    targetHost: config.targetHost,
    targetPort: config.targetPort,
  });

  // Build middleware chain in correct order:
  // 1. Request size limits (prevent resource exhaustion early)
  // 2. Security headers (set on all responses)
  // 3. Request tracking/correlation
  // 4. Health check (bypass security for health endpoint)
  // 5. Rate limiting (prevent DoS)
  // 6. Input validation (ensure data integrity)
  // 7. JWT authentication (verify identity)
  // 8. Proxy forwarding
  const middlewares: Middleware[] = [
    RequestSizeLimit.middleware({
      maxBodySize: 1048576, // 1MB
      maxUrlLength: 2048,
      maxHeaderSize: 8192,
    }),
    SecurityHeaders.middleware({
      enableHSTS: config.nodeEnv === 'production',
      enableFrameGuard: true,
      enableContentTypeNoSniff: true,
      enableXSSProtection: true,
    }),
    correlationIdMiddleware(),
    requestLoggingMiddleware(),
    healthCheckMiddleware(),
    rateLimiter.middleware(),
    InputValidator.middleware(),
    jwtValidator.middleware(),
  ];

  // Create HTTP server with middleware chain
  const server = http.createServer((req, res) => {
    executeMiddlewareChain(middlewares, req, res, () => {
      // Final handler: proxy the request
      proxyServer.handleRequest(req, res);
    });
  });

  // Start the gateway server
  server.listen(config.port, () => {
    logger.info(`Shield-TS Gateway listening on port ${config.port}`);
    logger.info(`Proxying requests to ${config.targetHost}:${config.targetPort}`);
  });

  // Graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`Received ${signal}, shutting down gracefully...`);

    server.close(() => {
      logger.info('HTTP server closed');
    });

    await rateLimiter.close();
    proxyServer.stop();

    if (backendServer) {
      backendServer.stop();
    }

    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Start the application
main().catch((error) => {
  logger.error({ error }, 'Failed to start application');
  process.exit(1);
});
