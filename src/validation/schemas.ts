import { z } from 'zod';

/**
 * Schema for User-Agent header validation
 * Prevents malicious patterns and ensures reasonable length
 */
export const userAgentSchema = z
  .string()
  .min(1, 'User-Agent cannot be empty')
  .max(500, 'User-Agent too long')
  .regex(
    /^[a-zA-Z0-9\s\-_./:;()[\]{}@!#$%&*+=|~`'"<>?,]+$/,
    'User-Agent contains invalid characters'
  );

/**
 * Schema for Authorization header validation
 * Note: Detailed JWT validation happens in JwtValidator middleware
 * This just ensures the header is present and non-empty
 */
export const authorizationSchema = z
  .string()
  .min(1, 'Authorization header cannot be empty');

/**
 * Schema for Content-Type header validation
 */
export const contentTypeSchema = z.enum([
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
]);

/**
 * Schema for general header validation
 * Prevents header injection attacks
 */
export const headerValueSchema = z
  .string()
  .max(8192, 'Header value too long') // RFC 7230 recommends 8KB limit
  .refine(
    (val) => !val.includes('\r') && !val.includes('\n'),
    'Header contains CRLF characters (potential injection attack)'
  )
  .refine(
    (val) => !val.includes('\x00'),
    'Header contains null bytes'
  );

/**
 * Schema for query parameter validation
 * Prevents SQL injection and XSS
 */
export const queryParamSchema = z
  .string()
  .max(2048, 'Query parameter too long')
  .refine(
    (val) => {
      // Check for SQL injection patterns
      const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
        /(union.*select)/i,
        /(or\s+1\s*=\s*1)/i,
        /(;.*--)/,
        /('.*or.*'.*=.*')/i,
      ];
      return !sqlPatterns.some((pattern) => pattern.test(val));
    },
    'Query parameter contains potential SQL injection'
  )
  .refine(
    (val) => {
      // Check for XSS patterns
      const xssPatterns = [
        /<script[^>]*>.*<\/script>/i,
        /javascript:/i,
        /on\w+\s*=/i, // Event handlers like onclick=
        /<iframe/i,
        /<embed/i,
        /<object/i,
      ];
      return !xssPatterns.some((pattern) => pattern.test(val));
    },
    'Query parameter contains potential XSS'
  );

/**
 * Schema for validating common HTTP headers
 */
export const commonHeadersSchema = z.object({
  'user-agent': userAgentSchema.optional(),
  'content-type': contentTypeSchema.optional(),
  host: headerValueSchema.optional(),
  accept: headerValueSchema.optional(),
  'accept-encoding': headerValueSchema.optional(),
  'accept-language': headerValueSchema.optional(),
  connection: headerValueSchema.optional(),
});

/**
 * Validate a single query parameter
 */
export function validateQueryParam(_key: string, value: string): {
  valid: boolean;
  error?: string;
} {
  try {
    queryParamSchema.parse(value);
    return { valid: true };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        valid: false,
        error: error.issues[0]?.message || 'Invalid query parameter',
      };
    }
    return { valid: false, error: 'Unknown validation error' };
  }
}

/**
 * Validate a single header
 */
export function validateHeader(key: string, value: string): {
  valid: boolean;
  error?: string;
} {
  try {
    // Special validation for specific headers
    if (key.toLowerCase() === 'authorization') {
      authorizationSchema.parse(value);
    } else if (key.toLowerCase() === 'user-agent') {
      userAgentSchema.parse(value);
    } else if (key.toLowerCase() === 'content-type') {
      contentTypeSchema.parse(value);
    } else {
      headerValueSchema.parse(value);
    }
    return { valid: true };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        valid: false,
        error: error.issues[0]?.message || 'Invalid header value',
      };
    }
    return { valid: false, error: 'Unknown validation error' };
  }
}
