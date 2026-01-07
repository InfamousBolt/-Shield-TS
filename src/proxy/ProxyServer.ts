import http from 'http';
import httpProxy from 'http-proxy';
import logger from '../logging/Logger';
import { logSecurityEvent } from '../logging/Logger';
import { SecurityEventType } from '../logging/SecurityEvents';

export interface ProxyConfig {
  port: number;
  targetHost: string;
  targetPort: number;
  timeout?: number;
}

export class ProxyServer {
  private server?: http.Server;
  private proxy: httpProxy;
  private config: ProxyConfig;

  constructor(config: ProxyConfig) {
    this.config = {
      timeout: 30000, // 30 seconds default
      ...config,
    };

    // Create proxy instance
    this.proxy = httpProxy.createProxyServer({
      target: `http://${this.config.targetHost}:${this.config.targetPort}`,
      timeout: this.config.timeout,
      proxyTimeout: this.config.timeout,
      changeOrigin: true,
    });

    // Handle proxy errors
    this.proxy.on('error', (err, req, res) => {
      logger.error({ error: err.message, url: req.url }, 'Proxy error occurred');

      logSecurityEvent({
        type: SecurityEventType.PROXY_ERROR,
        timestamp: new Date().toISOString(),
        path: req.url,
        message: `Proxy error: ${err.message}`,
        details: { error: err.message },
      });

      // Send error response if response hasn't been sent yet
      if (res && res instanceof http.ServerResponse && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Bad Gateway',
            message: 'The gateway encountered an error while processing your request',
          })
        );
      }
    });

    // Log successful proxy requests
    this.proxy.on('proxyRes', (proxyRes, req) => {
      logger.debug(
        {
          url: req.url,
          method: req.method,
          statusCode: proxyRes.statusCode,
        },
        'Request proxied successfully'
      );
    });
  }

  public getServer(): http.Server {
    if (!this.server) {
      throw new Error('Server not created. Call createServer() first.');
    }
    return this.server;
  }

  public createServer(): http.Server {
    this.server = http.createServer((req, res) => {
      // Middleware chain will be attached to this server externally
      // For now, just proxy the request
      this.handleRequest(req, res);
    });

    return this.server;
  }

  public handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): void {
    // This method will be called by the middleware chain
    // after all security checks pass
    this.proxy.web(req, res);
  }

  public start(): void {
    if (!this.server) {
      this.createServer();
    }

    this.server!.listen(this.config.port, () => {
      logger.info(
        {
          gatewayPort: this.config.port,
          targetHost: this.config.targetHost,
          targetPort: this.config.targetPort,
        },
        `Proxy server listening on port ${this.config.port}`
      );
    });
  }

  public stop(): void {
    if (this.server) {
      this.server.close(() => {
        logger.info('Proxy server stopped');
      });
    }
    this.proxy.close();
  }
}
