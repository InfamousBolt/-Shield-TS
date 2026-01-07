# 🛡️ Shield-TS: Production-Grade API Gateway

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![Redis](https://img.shields.io/badge/Redis-7-red.svg)](https://redis.io/)

A **zero-trust API gateway** built with TypeScript that acts as a security proxy, enforcing architectural invariants before forwarding requests to backend microservices. Designed with production-grade security patterns used by companies like Stripe.

## 🎯 Key Features

### Security-First Architecture
- **Zero-Trust Authentication**: RS256 JWT validation on every request using asymmetric key pairs
- **Fail-Closed Rate Limiting**: Redis-backed sliding window that defaults to restrictive limits on infrastructure failure
- **Request Size Limits**: DoS protection with configurable URL, header, and body size constraints
- **Security Headers**: OWASP-recommended headers (CSP, HSTS, X-Frame-Options, etc.)
- **Input Validation**: Zod-based schema validation preventing XSS and SQL injection
- **Structured Security Logging**: Pino logger with automatic sensitive data redaction

### Production-Ready Features
- **Type-Safe**: Built with TypeScript in strict mode for compile-time safety
- **Comprehensive Testing**: Jest test suite with table-driven patterns and edge case coverage
- **Docker Support**: Multi-stage builds with Docker Compose orchestration
- **Graceful Shutdown**: Proper cleanup of Redis connections and HTTP servers
- **Request Tracing**: Correlation IDs for distributed request tracking

## 🏗️ Architecture

### Security Pipeline

Every request flows through a strict, ordered security pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│  1. Request Size Limits      (DoS Protection)               │
│  2. Security Headers          (OWASP Compliance)            │
│  3. Correlation ID            (Request Tracking)            │
│  4. Request Logging           (Audit Trail)                 │
│  5. Health Check Bypass       (Monitoring)                  │
│  6. Rate Limiting             (Redis Sliding Window)        │
│  7. Input Validation          (Zod Schemas)                 │
│  8. JWT Authentication        (RS256 Verification)          │
│  9. Proxy Forwarding          (Backend Routing)             │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

- **Runtime**: Node.js 20+ with TypeScript 5.9
- **Proxy**: `http-proxy` for low-level HTTP forwarding
- **Authentication**: `jsonwebtoken` with RS256 asymmetric signatures
- **Rate Limiting**: `ioredis` with Redis sorted sets for distributed state
- **Validation**: Zod for type-safe schema enforcement
- **Logging**: Pino for high-performance structured logging
- **Testing**: Jest with TypeScript support

## 🚀 Quick Start

### Prerequisites

- Node.js 20+
- Redis 7+ (optional for development - gateway works in fail-closed mode)
- Docker & Docker Compose (optional)

### Installation

1. **Clone and Install**
```bash
git clone https://github.com/yourusername/shield-ts.git
cd shield-ts
npm install
```

2. **Generate JWT Keys**
```bash
npm run generate-keys
```
This creates RSA key pairs in `keys/` directory (2048-bit, PKCS#8 format).

3. **Start Redis** (Optional)
```bash
# Using Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or using Docker Compose
docker-compose up redis -d
```

4. **Run Development Server**
```bash
npm run dev
```

The gateway starts on `http://localhost:3000` with a mock backend on port 4000.

## 📖 Usage

### Generate Test Token

```bash
npm run generate-token
```

### Make Authenticated Request

```bash
# Export token
export TOKEN=$(npm run generate-token --silent | grep "^eyJ")

# Access protected endpoint
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/protected
```

### Example Response

```json
{
  "message": "Protected resource accessed successfully",
  "userId": "user123",
  "timestamp": "2026-01-07T01:23:09.585Z",
  "data": {
    "secret": "This is sensitive data",
    "resourceId": "12345"
  }
}
```

## 🔧 Configuration

Copy `.env.example` to `.env`:

```bash
# Server Configuration
PORT=3000
NODE_ENV=development
TARGET_HOST=localhost
TARGET_PORT=4000

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000              # 1 minute
RATE_LIMIT_MAX_REQUESTS=100             # Normal limit
RATE_LIMIT_FAIL_CLOSED_LIMIT=10         # Fail-closed limit

# JWT
JWT_PUBLIC_KEY_PATH=./keys/public.pem

# Request Limits
MAX_URL_LENGTH=2048                     # 2KB
MAX_HEADER_SIZE=8192                    # 8KB
MAX_BODY_SIZE=1048576                   # 1MB
```

## 🔒 Security Features

### 1. Fail-Closed Rate Limiting

When Redis is **unavailable**, the gateway automatically switches to a restrictive in-memory rate limiter (10 requests/minute by default) instead of failing open. This prevents DoS attacks during infrastructure failures.

```typescript
// Redis healthy: 100 req/min per client
// Redis down:    10 req/min per client (fail-closed)
```

### 2. Zero-Trust Authentication

Every request (except `/health`) requires a valid RS256 JWT. The gateway uses **asymmetric verification** - only the public key is loaded, preventing token forgery.

### 3. Security Headers

All responses include OWASP-recommended headers:
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 4. Security Event Logging

All security events are logged with structured JSON:
- `AUTH_FAILURE` - Invalid/missing JWT
- `RATE_LIMIT_EXCEEDED` - Client exceeded limit
- `MALFORMED_INPUT` - Schema validation failure
- `REDIS_CONNECTION_FAILURE` - Fail-closed mode activated
- `EXPIRED_JWT` - Token expiration
- `INVALID_JWT` - Signature verification failure

## 🧪 Testing

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# Coverage report
npm run test:coverage
```

**Test Coverage**: 43+ passing tests covering:
- JWT validation (expiration boundaries, invalid signatures, malformed tokens)
- Input validation (XSS patterns, SQL injection, schema enforcement)
- Integration pipeline (complete request flows)
- Edge cases (token expired by exactly 1 second, etc.)

## 🐳 Docker Deployment

### Development
```bash
docker-compose up
```

### Production Build
```bash
docker-compose up --build -d
```

The `Dockerfile` uses multi-stage builds for optimized image size.

## 📊 Monitoring

### Health Check Endpoint

```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "healthy",
  "service": "shield-ts-gateway",
  "timestamp": "2026-01-07T01:13:07.738Z"
}
```

### Rate Limit Headers

Every response includes rate limit information:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1767748476096
```

### Request Tracing

Each request gets a unique correlation ID:
```
X-Correlation-Id: 1767748387738-r79l9
```

## 🏗️ Project Structure

```
shield-ts/
├── src/
│   ├── config/           # Environment configuration
│   ├── logging/          # Pino logger setup
│   ├── middleware/       # Security middlewares
│   │   ├── JwtValidator.ts
│   │   ├── RateLimiter.ts
│   │   ├── InputValidator.ts
│   │   ├── SecurityHeaders.ts
│   │   └── RequestSizeLimit.ts
│   ├── mock/             # Mock backend server
│   ├── proxy/            # HTTP proxy setup
│   ├── validation/       # Zod schemas
│   └── index.ts          # Main entry point
├── tests/                # Jest test suites
│   ├── middleware/       # Unit tests
│   └── integration/      # Integration tests
├── scripts/              # Utility scripts
│   ├── generate-keys.ts
│   └── generate-test-token.ts
├── keys/                 # JWT keys (git-ignored)
├── docker-compose.yml
├── Dockerfile
└── package.json
```

## 🔧 Development

```bash
# Linting
npm run lint

# Code formatting
npm run format

# Build TypeScript
npm run build

# Run production build
npm start
```

## 🎓 Learning Resources

This project demonstrates:
- **Security Architecture**: Zero-trust principles, defense in depth
- **Production Patterns**: Graceful shutdown, structured logging, fail-closed design
- **TypeScript Best Practices**: Strict mode, type safety, interface design
- **Testing Strategies**: Table-driven tests, edge case coverage, integration testing
- **DevOps**: Docker multi-stage builds, environment configuration, health checks

## 📝 Security Invariants

✅ **Zero-Trust**: No request forwarded without valid, verified identity
✅ **Fail-Closed**: Infrastructure failures default to restrictive security
✅ **Type Safety**: All inputs validated with compile-time + runtime checks
✅ **Audit Trail**: All security events logged with correlation IDs
✅ **No Secrets in Logs**: Automatic redaction of tokens and credentials
✅ **Request Size Limits**: DoS protection at gateway level
✅ **Rate Limiting**: Per-client limits with distributed state

---

**Built with ❤️ and TypeScript**
