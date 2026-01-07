# Testing Guide for Shield-TS Gateway

This guide walks through testing all Day 1 features.

## Prerequisites

1. Dependencies installed: `npm install` ✅
2. JWT keys generated: `npm run generate-keys` ✅
3. Build completed: `npm run build` ✅

## Step 1: Start Redis

Option A - Using Docker:
```bash
docker run -d --name shield-redis -p 6379:6379 redis:7-alpine
```

Option B - Using Docker Compose:
```bash
docker-compose up -d redis
```

Verify Redis is running:
```bash
docker ps | grep redis
```

## Step 2: Start the Gateway

In a terminal window:
```bash
npm run dev
```

You should see:
- Mock backend server starting on port 4000
- Gateway starting on port 3000
- Redis connection established

## Step 3: Test Health Check (No Auth Required)

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "shield-ts-gateway",
  "timestamp": "2024-01-06T..."
}
```

## Step 4: Generate Test JWT Token

```bash
npm run generate-token
```

Copy the token from the output. Or save it to a variable:
```bash
TOKEN=$(npm run generate-token 2>/dev/null | tail -n 1)
echo $TOKEN
```

## Step 5: Test Authenticated Request

```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "User-Agent: TestClient/1.0" \
     http://localhost:3000/api/protected
```

Expected response (200 OK):
```json
{
  "message": "Protected resource accessed successfully",
  "userId": "user123",
  "timestamp": "...",
  "data": {
    "secret": "This is sensitive data",
    "resourceId": "12345"
  }
}
```

Check the rate limit headers:
```bash
curl -i -H "Authorization: Bearer $TOKEN" \
        -H "User-Agent: TestClient/1.0" \
        http://localhost:3000/api/protected
```

Look for:
- `X-RateLimit-Limit: 100`
- `X-RateLimit-Remaining: 99`
- `X-RateLimit-Reset: <timestamp>`

## Step 6: Test Rate Limiting

Make 100+ requests rapidly:
```bash
for i in {1..105}; do
  echo "Request $i:"
  curl -H "Authorization: Bearer $TOKEN" \
       -H "User-Agent: TestClient/1.0" \
       http://localhost:3000/api/protected
  echo ""
done
```

After request 100, you should see (429 Too Many Requests):
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Please try again later.",
  "retryAfter": 60
}
```

## Step 7: Test JWT Validation Failures

### Missing Authorization Header
```bash
curl http://localhost:3000/api/protected
```

Expected (401 Unauthorized):
```json
{
  "error": "Unauthorized",
  "message": "Authorization token required"
}
```

### Invalid Token
```bash
curl -H "Authorization: Bearer invalid.token.here" \
     http://localhost:3000/api/protected
```

Expected (401 Unauthorized):
```json
{
  "error": "Unauthorized",
  "message": "Invalid authentication token"
}
```

### Malformed Authorization Header
```bash
curl -H "Authorization: NotBearer $TOKEN" \
     http://localhost:3000/api/protected
```

Expected (400 Bad Request):
```json
{
  "error": "Bad Request",
  "message": "Invalid request headers",
  "field": "authorization"
}
```

## Step 8: Test Input Validation

### Missing User-Agent
```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/protected
```

Should work (User-Agent is optional)

### SQL Injection in Query Parameter
```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "User-Agent: TestClient/1.0" \
     "http://localhost:3000/api/users/1?search=test' OR '1'='1"
```

Expected (400 Bad Request):
```json
{
  "error": "Bad Request",
  "message": "Invalid query parameters",
  "field": "query.search"
}
```

### XSS in Query Parameter
```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "User-Agent: TestClient/1.0" \
     "http://localhost:3000/api/protected?q=<script>alert('xss')</script>"
```

Expected (400 Bad Request):
```json
{
  "error": "Bad Request",
  "message": "Invalid query parameters"
}
```

## Step 9: Test Fail-Closed Behavior

### Stop Redis
```bash
docker stop shield-redis
```

### Make Request (Should Use Restrictive Fallback)
```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "User-Agent: TestClient/1.0" \
     http://localhost:3000/api/protected
```

First 10 requests should work (fail-closed limit = 10)
After that, you'll get 429 Too Many Requests

Check gateway logs for:
```
Using fail-closed rate limiting (Redis unavailable)
```

### Restart Redis
```bash
docker start shield-redis
```

The gateway should automatically reconnect.

## Step 10: Check Security Logs

In the gateway terminal, you should see structured logs:

- `AUTH_FAILURE` - when invalid JWT provided
- `RATE_LIMIT_EXCEEDED` - when rate limit hit
- `MALFORMED_INPUT` - when validation fails
- `REDIS_CONNECTION_FAILURE` - when Redis goes down

## Cleanup

Stop the gateway: `Ctrl+C`

Stop Redis:
```bash
docker stop shield-redis
docker rm shield-redis
```

Or with Docker Compose:
```bash
docker-compose down
```

## Summary

✅ Health check bypasses security
✅ Rate limiting enforced (100 req/min)
✅ JWT validation required for protected endpoints
✅ Input validation blocks XSS and SQL injection
✅ Fail-closed mode activates when Redis is down
✅ Security events logged properly
