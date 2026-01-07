# Shield-TS: Secure-by-Default API Gateway

A high-performance security proxy designed to enforce architectural invariants. Built with **TypeScript** to provide type-safe security primitives and **Redis** for distributed state management.

## 🛠 Tech Stack

- **Language:** TypeScript / Node.js (for high-concurrency I/O).
- **Library:** `http-proxy` (for low-level proxy control).
- **Data Store:** Redis (for distributed rate limiting).
- **Auth:** JWT with RS256 Asymmetric signatures.
- **Validation:** Zod (for strict schema enforcement).

## 🏗 System Architecture

1. **The Inbound Layer:** Intercepts raw HTTP requests.
2. **Rate Limiting Middleware:** Redis-backed sliding window to prevent DoS.
3. **Identity Layer:** Validates RS256 JWTs using a public key.
4. **Schema Invariant Layer:** Uses Zod to ensure headers and query params match strict security definitions.
5. **The Proxy Layer:** Transparently forwards "Clean" requests to internal microservices.

---

## 📅 Weekend Execution Plan

### Day 1: The Proxy & Rate Limiting

- **Morning: Core Proxy Setup**
  - Initialize a TypeScript project with `ts-node`.
  - Set up `http-proxy` to forward requests to a mock Express server.
  - Create a `docker-compose.yml` for the Gateway + Redis.
- **Afternoon: Redis Rate Limiter**
  - Use `ioredis` to implement a **Sliding Window** rate limiter.
  - **Security Goal:** Implement a "Fail-Closed" mechanism—if Redis is unreachable, the gateway should default to a more restrictive rate limit to protect the backend.
- **Evening: Input Sanitization**
  - Create a middleware that uses **Zod** to validate that incoming headers (like `User-Agent` or `Authorization`) don't contain malicious patterns.

### Day 2: Identity & Reliability

- **Morning: RS256 JWT Validation**
  - Implement a middleware using `jsonwebtoken`.
  - **Logic:** Validate the signature using an asymmetric public key. This mimics how Stripe handles cross-service identity.
- **Afternoon: Security Logging**
  - Implement structured logging with `Winston` or `Pino`.
  - Log "Security Events" like: `AUTH_FAILURE`, `RATE_LIMIT_EXCEEDED`, and `MALFORMED_INPUT`.
- **Evening: Table-Driven Testing**
  - Use `Jest` to write tests for your security middlewares.
  - **Rigor Check:** Test "Edge cases"—e.g., what happens if the JWT is expired by exactly 1 second?

---

## 🛡 Security Invariants Enforced

- **Zero-Trust:** No request is forwarded without a valid, verified identity.
- **Resource Protection:** Rate limiting ensures the backend is never overwhelmed.
- **Type Safety:** The proxy guarantees that the backend only receives data in the expected format.
