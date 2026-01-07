import http from 'http';
import { URL } from 'url';
import { validateHeader, validateQueryParam } from '../validation/schemas';
import logger, { logSecurityEvent } from '../logging/Logger';
import { SecurityEventType, MalformedInputEvent } from '../logging/SecurityEvents';

export class InputValidator {
  /**
   * Headers that should be validated
   */
  private static readonly HEADERS_TO_VALIDATE = [
    'user-agent',
    'authorization',
    'content-type',
    'referer',
    'origin',
    'host',
  ];

  /**
   * Get client IP for logging
   */
  private static getClientIp(req: http.IncomingMessage): string {
    const forwarded = req.headers['x-forwarded-for'] as string;
    return forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress || 'unknown';
  }

  /**
   * Validate request headers
   */
  private static validateHeaders(req: http.IncomingMessage): {
    valid: boolean;
    field?: string;
    error?: string;
    value?: string;
  } {
    for (const headerName of this.HEADERS_TO_VALIDATE) {
      const headerValue = req.headers[headerName];

      // Skip if header is not present and not required
      if (!headerValue) {
        continue;
      }

      // Validate the header value
      const result = validateHeader(
        headerName,
        Array.isArray(headerValue) ? headerValue[0] : headerValue
      );

      if (!result.valid) {
        return {
          valid: false,
          field: headerName,
          error: result.error,
          value: Array.isArray(headerValue) ? headerValue[0] : headerValue,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Validate query parameters
   */
  private static validateQueryParams(req: http.IncomingMessage): {
    valid: boolean;
    field?: string;
    error?: string;
    value?: string;
  } {
    // Parse URL to extract query parameters
    const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
    const params = url.searchParams;

    for (const [key, value] of params.entries()) {
      const result = validateQueryParam(key, value);

      if (!result.valid) {
        return {
          valid: false,
          field: `query.${key}`,
          error: result.error,
          value,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Input validation middleware
   */
  public static middleware() {
    return (
      req: http.IncomingMessage,
      res: http.ServerResponse,
      next: () => void
    ): void => {
      const clientIp = this.getClientIp(req);

      // Validate headers
      const headerValidation = this.validateHeaders(req);
      if (!headerValidation.valid) {
        logger.warn(
          {
            field: headerValidation.field,
            error: headerValidation.error,
            ip: clientIp,
            url: req.url,
          },
          'Malformed header detected'
        );

        logSecurityEvent({
          type: SecurityEventType.MALFORMED_INPUT,
          timestamp: new Date().toISOString(),
          ip: clientIp,
          path: req.url,
          message: `Malformed header: ${headerValidation.field}`,
          field: headerValidation.field!,
          value: headerValidation.value?.substring(0, 100), // Truncate for logging
          validationError: headerValidation.error!,
        } as MalformedInputEvent);

        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Bad Request',
            message: 'Invalid request headers',
            field: headerValidation.field,
          })
        );
        return;
      }

      // Validate query parameters
      const queryValidation = this.validateQueryParams(req);
      if (!queryValidation.valid) {
        logger.warn(
          {
            field: queryValidation.field,
            error: queryValidation.error,
            ip: clientIp,
            url: req.url,
          },
          'Malformed query parameter detected'
        );

        logSecurityEvent({
          type: SecurityEventType.MALFORMED_INPUT,
          timestamp: new Date().toISOString(),
          ip: clientIp,
          path: req.url,
          message: `Malformed query parameter: ${queryValidation.field}`,
          field: queryValidation.field!,
          value: queryValidation.value?.substring(0, 100), // Truncate for logging
          validationError: queryValidation.error!,
        } as MalformedInputEvent);

        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Bad Request',
            message: 'Invalid query parameters',
            field: queryValidation.field,
          })
        );
        return;
      }

      // All validations passed
      logger.debug({ url: req.url, ip: clientIp }, 'Input validation passed');
      next();
    };
  }
}
