import http from 'http';
import logger from '../logging/Logger';

export interface RequestSizeLimitConfig {
  maxBodySize?: number; // in bytes
  maxUrlLength?: number; // in characters
  maxHeaderSize?: number; // in bytes
}

/**
 * Request Size Limit Middleware
 * Prevents DoS attacks via large requests
 */
export class RequestSizeLimit {
  private config: Required<RequestSizeLimitConfig>;

  constructor(config: RequestSizeLimitConfig = {}) {
    this.config = {
      maxBodySize: config.maxBodySize ?? 1048576, // 1MB default
      maxUrlLength: config.maxUrlLength ?? 2048, // 2KB default
      maxHeaderSize: config.maxHeaderSize ?? 8192, // 8KB default
    };
  }

  /**
   * Calculate approximate size of headers
   */
  private getHeadersSize(headers: http.IncomingHttpHeaders): number {
    let size = 0;
    for (const [key, value] of Object.entries(headers)) {
      if (value) {
        const valueStr = Array.isArray(value) ? value.join(', ') : value;
        size += key.length + valueStr.length + 4; // +4 for ": " and "\r\n"
      }
    }
    return size;
  }

  /**
   * Middleware function to enforce size limits
   */
  public static middleware(config?: RequestSizeLimitConfig) {
    const instance = new RequestSizeLimit(config);

    return (
      req: http.IncomingMessage,
      res: http.ServerResponse,
      next: () => void
    ): void => {
      // Check URL length
      if (req.url && req.url.length > instance.config.maxUrlLength) {
        logger.warn(
          {
            url: req.url.substring(0, 100),
            urlLength: req.url.length,
            maxAllowed: instance.config.maxUrlLength,
          },
          'Request URL too long'
        );

        res.writeHead(414, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'URI Too Long',
            message: 'Request URL exceeds maximum allowed length',
          })
        );
        return;
      }

      // Check headers size
      const headersSize = instance.getHeadersSize(req.headers);
      if (headersSize > instance.config.maxHeaderSize) {
        logger.warn(
          {
            headersSize,
            maxAllowed: instance.config.maxHeaderSize,
          },
          'Request headers too large'
        );

        res.writeHead(431, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Request Header Fields Too Large',
            message: 'Request headers exceed maximum allowed size',
          })
        );
        return;
      }

      // Check body size (for POST, PUT, PATCH requests)
      if (req.method && ['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentLength = req.headers['content-length'];

        if (contentLength) {
          const bodySize = parseInt(contentLength, 10);

          if (bodySize > instance.config.maxBodySize) {
            logger.warn(
              {
                bodySize,
                maxAllowed: instance.config.maxBodySize,
                method: req.method,
                url: req.url,
              },
              'Request body too large'
            );

            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Payload Too Large',
                message: 'Request body exceeds maximum allowed size',
                maxSize: instance.config.maxBodySize,
              })
            );
            return;
          }
        }

        // Set up streaming size check for chunked encoding
        let receivedBytes = 0;
        req.on('data', (chunk: Buffer) => {
          receivedBytes += chunk.length;

          if (receivedBytes > instance.config.maxBodySize) {
            logger.warn(
              {
                receivedBytes,
                maxAllowed: instance.config.maxBodySize,
              },
              'Request body exceeded limit during streaming'
            );

            req.pause();
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Payload Too Large',
                message: 'Request body exceeds maximum allowed size',
              })
            );
            req.removeAllListeners('data');
            req.removeAllListeners('end');
          }
        });
      }

      next();
    };
  }
}
