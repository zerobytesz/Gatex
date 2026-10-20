# Architecture

## Request pipeline

1. **IpThreatWebFilter** (WebFilter, order -200, runs before Spring Security)
   - Skips excluded paths (dashboard, actuator, admin API).
   - Resolves the client IP from the TCP peer, or from `X-Forwarded-For` only when `trust-forwarded-headers` is on.
   - Counts the request toward global traffic health.
   - Evaluates the IP-scope profile. If it is blocked or rate-limited, responds with 429 straight away.
   - After the response, records the HTTP status as evidence (401 on `/auth/login` counts as a failed login) and writes one audit event.
2. **Spring Security** validates the JWT (HS256, issuer and expiry) and enforces roles.
3. **ThreatDetectionGlobalFilter** (Spring Cloud Gateway GlobalFilter, order 100)
   - Evaluates the user-scope profile keyed by the JWT subject.
   - Applies the action: allow, throttle (non-blocking delay), rate-limit (429) or block (429).
   - Forwards `X-Authenticated-User` and `X-User-Role` to the backend and strips any client-supplied identity headers.
   - Records the backend's response status as evidence.
4. **Routing** sends `/api/users/**` to user-service and `/api/orders/**` to order-service.
5. **Audit and metrics**
   - Events go to an in-memory ring buffer (dashboard) and are written to MySQL in batches every second.
   - Blacklist entries are written to MySQL and restored on start-up.
   - Micrometer metrics are exposed for Prometheus.

## Threat engine

`ThreatEngine` is plain Java with no Spring imports. It takes a `ThreatProperties` object and a clock, which is why
it can be tested deterministically with a simulated clock (see `ThreatEngineTest`).

Each client profile keeps:
- a sliding window of request timestamps
- decaying evidence counters: burst points, failures, suspicious paths, failed logins
- a token bucket
- block state and an offence count

Each request is evaluated in this order:
1. If the client is blocked, return BLOCK without counting the request.
2. Decay the evidence, slide the window, and add this request.
3. If the path matches a suspicious pattern, increment the suspicious counter.
4. If the window exceeds the limit, add burst points.
5. Compute the risk score and derive the threat level.
6. If the level is CRITICAL, block the client for `blockSeconds × 2^offences` (capped at `2^maxBlockEscalation`) and notify the listener (persistence).
7. Otherwise refill the bucket using the level's capacity and refill rate × the global health factor. An empty bucket means RATE_LIMITED; otherwise the result is ALLOW, THROTTLE or STRONG_THROTTLE depending on the level.

## Data model

| Table | Purpose |
|---|---|
| `app_users` | username, BCrypt hash, role |
| `security_events` | timestamp, client key, IP, method, path, status, risk, level, action (kept for 7 days by default) |
| `client_blacklist` | client key, blocked-until, offences, reason |

## Extension points (future scope)

- **ML anomaly detection**: add a model that consumes the same per-client features (rate, burst, failures, suspicious paths, failed logins, latency) and contributes a term to the risk score, or replaces `risk(...)`.
- **Distributed deployment / Kubernetes**: move the profiles and blacklist to a shared store such as Redis so that several gateway replicas see the same state.
- **Zero Trust**: mutual TLS between the gateway and backends, and short-lived tokens issued by an external identity provider.
