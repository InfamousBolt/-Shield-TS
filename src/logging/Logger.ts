import pino from 'pino';
import { SecurityEvent, SecurityEventType } from './SecurityEvents';

const isDevelopment = process.env.NODE_ENV === 'development';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: isDevelopment
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  // Redact sensitive fields to prevent leaking credentials
  redact: {
    paths: ['authorization', 'password', 'token', 'secret', 'apiKey'],
    remove: true,
  },
});

/**
 * Log a security event with structured data
 */
export function logSecurityEvent(event: SecurityEvent): void {
  const logData = {
    eventType: event.type,
    timestamp: event.timestamp,
    ip: event.ip,
    userId: event.userId,
    path: event.path,
    message: event.message,
    ...event.details,
  };

  // Use appropriate log level based on event type
  switch (event.type) {
    case SecurityEventType.AUTH_FAILURE:
    case SecurityEventType.INVALID_JWT:
    case SecurityEventType.EXPIRED_JWT:
    case SecurityEventType.MALFORMED_INPUT:
      logger.warn(logData, event.message);
      break;
    case SecurityEventType.RATE_LIMIT_EXCEEDED:
      logger.warn(logData, event.message);
      break;
    case SecurityEventType.REDIS_CONNECTION_FAILURE:
    case SecurityEventType.PROXY_ERROR:
      logger.error(logData, event.message);
      break;
    default:
      logger.info(logData, event.message);
  }
}

export default logger;
