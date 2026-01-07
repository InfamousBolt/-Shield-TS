export enum SecurityEventType {
  AUTH_FAILURE = 'AUTH_FAILURE',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  MALFORMED_INPUT = 'MALFORMED_INPUT',
  REDIS_CONNECTION_FAILURE = 'REDIS_CONNECTION_FAILURE',
  PROXY_ERROR = 'PROXY_ERROR',
  INVALID_JWT = 'INVALID_JWT',
  EXPIRED_JWT = 'EXPIRED_JWT',
}

export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: string;
  ip?: string;
  userId?: string;
  path?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface RateLimitEvent extends SecurityEvent {
  type: SecurityEventType.RATE_LIMIT_EXCEEDED;
  limit: number;
  window: number;
  requestCount: number;
}

export interface AuthFailureEvent extends SecurityEvent {
  type: SecurityEventType.AUTH_FAILURE | SecurityEventType.INVALID_JWT | SecurityEventType.EXPIRED_JWT;
  reason: string;
}

export interface MalformedInputEvent extends SecurityEvent {
  type: SecurityEventType.MALFORMED_INPUT;
  field: string;
  value?: string;
  validationError: string;
}
