import http from 'http';

export interface SecurityHeadersConfig {
  enableHSTS?: boolean;
  hstsMaxAge?: number;
  enableFrameGuard?: boolean;
  enableContentTypeNoSniff?: boolean;
  enableXSSProtection?: boolean;
  contentSecurityPolicy?: string;
  referrerPolicy?: string;
}

/**
 * Security Headers Middleware
 * Adds security-related HTTP headers to responses
 */
export class SecurityHeaders {
  private config: Required<SecurityHeadersConfig>;

  constructor(config: SecurityHeadersConfig = {}) {
    this.config = {
      enableHSTS: config.enableHSTS ?? true,
      hstsMaxAge: config.hstsMaxAge ?? 31536000, // 1 year in seconds
      enableFrameGuard: config.enableFrameGuard ?? true,
      enableContentTypeNoSniff: config.enableContentTypeNoSniff ?? true,
      enableXSSProtection: config.enableXSSProtection ?? true,
      contentSecurityPolicy:
        config.contentSecurityPolicy ?? "default-src 'self'; frame-ancestors 'none'",
      referrerPolicy: config.referrerPolicy ?? 'strict-origin-when-cross-origin',
    };
  }

  /**
   * Middleware function to add security headers
   */
  public static middleware(config?: SecurityHeadersConfig) {
    const instance = new SecurityHeaders(config);

    return (
      _req: http.IncomingMessage,
      res: http.ServerResponse,
      next: () => void
    ): void => {
      // HSTS - Force HTTPS
      if (instance.config.enableHSTS) {
        res.setHeader(
          'Strict-Transport-Security',
          `max-age=${instance.config.hstsMaxAge}; includeSubDomains`
        );
      }

      // X-Frame-Options - Prevent clickjacking
      if (instance.config.enableFrameGuard) {
        res.setHeader('X-Frame-Options', 'DENY');
      }

      // X-Content-Type-Options - Prevent MIME sniffing
      if (instance.config.enableContentTypeNoSniff) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }

      // X-XSS-Protection - Enable XSS filter (legacy browsers)
      if (instance.config.enableXSSProtection) {
        res.setHeader('X-XSS-Protection', '1; mode=block');
      }

      // Content-Security-Policy - Prevent XSS and data injection
      if (instance.config.contentSecurityPolicy) {
        res.setHeader('Content-Security-Policy', instance.config.contentSecurityPolicy);
      }

      // Referrer-Policy - Control referrer information
      res.setHeader('Referrer-Policy', instance.config.referrerPolicy);

      // X-Permitted-Cross-Domain-Policies - Restrict Adobe Flash/PDF
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

      // Remove X-Powered-By header (if present from underlying frameworks)
      res.removeHeader('X-Powered-By');

      next();
    };
  }
}
