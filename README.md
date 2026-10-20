# Smart API Gateway with Adaptive Threat Detection

A Java / Spring-based API gateway that authenticates clients with JWT, routes requests to backend microservices,
**observes client behaviour in real time** and **adapts its security policy automatically**. Suspicious clients are
first rate-limited and throttled, then temporarily blacklisted. No administrator has to step in.

Advanced Java Programming project (Review I proposal → implementation), VIT Vellore.

| PPT item | Implementation |
|---|---|
| Spring Boot, Spring Cloud Gateway | `gateway` module (reactive Spring Cloud Gateway, Netty) |
| Spring Security, JWT | Stateless JWT (HS256) resource server, BCrypt password hashing, USER / ADMIN roles |
| Authenticate | `/auth/login`, `/auth/register`; every API route requires a valid JWT |
| Limit & Throttle | Adaptive token bucket per client; capacity and refill shrink as the threat level rises and when global traffic exceeds capacity |
| Detect | Behavioural risk score from request rate, bursts, failed responses, suspicious paths (injection / traversal / admin probing) and failed logins |
| Mitigate | Automatic temporary blacklist of the IP or user, longer for repeat offenders, persisted in MySQL |
| MySQL (config / logs) | Users, security audit log and blacklist tables (MySQL in Docker, embedded H2 for quick local runs) |
| Prometheus, Grafana | Micrometer metrics at `/actuator/prometheus` and a provisioned Grafana dashboard |
| Maven, Docker, Postman, JMeter | Multi-module Maven build, Dockerfile + Docker Compose, Postman collection, JMeter test plan |

See [`docs/ppt-mapping.md`](docs/ppt-mapping.md) for a slide-by-slide mapping.

---

## Architecture

```text
                 ┌──────────────────────────── Smart API Gateway :8080 ────────────────────────────┐
 Client ──HTTP──▶│ 1 IpThreatWebFilter   IP blacklist · IP-scope risk · global traffic health      │
                 │ 2 Spring Security     JWT validation · roles (USER / ADMIN)                     │
                 │ 3 ThreatDetection     user-scope risk · adaptive token bucket · throttle/block  │
                 │   GlobalFilter                                                                  │
                 │ 4 Spring Cloud        /api/users/**  ──▶ user-service  :8081                    │
                 │   Gateway routes      /api/orders/** ──▶ order-service :8082                    │
                 │ 5 Audit + metrics     MySQL (events, blacklist) · Prometheus · live dashboard   │
                 └─────────────────────────────────────────────────────────────────────────────────┘
```

**Threat levels and actions**

| Risk score | Level | Action |
|---|---|---|
| 0–29 | LOW | Allow (token bucket 40 / 10 per s) |
| 30–59 | MEDIUM | Throttle: +100 ms and a tighter bucket (20 / 4 per s) |
| 60–79 | HIGH | Strong throttle: +300 ms and a strict bucket (8 / 1 per s) |
| ≥ 80 | CRITICAL | Temporary block with HTTP 429: 60 s, then 120 s, 240 s… for repeat offences |

**Risk model** (all weights configurable in `application.yml`). Evidence decays with τ = 60 s:

```
R = min(100,  min(60, 2·max(0, n − L))      excess requests in the 10 s window (L = 50 per user, 250 per IP)
            + min(30, B)                     accumulated burst points
            + min(25, 5·F)                   failed responses (4xx/5xx, excluding the gateway's own 429)
            + min(60, 15·S)                  suspicious paths (SQL injection, XSS, path traversal, /admin probing)
            + min(80, 12·G) )                failed logins
```

Design decisions:
- **Identity comes from the verified JWT subject** (user scope) and the TCP peer address (IP scope). It never comes from a header the client can set, so an attacker can't dodge detection by changing an ID.
- **Requests made while blocked are not counted.** A blocked client always regains access when its block expires.
- **The gateway's own 429 responses are not counted as evidence**, so mitigation can't feed back into the score.
- **Idle profiles are evicted** and the number of profiles is capped, so rotating identities can't exhaust memory.

---

## Requirements

- **JDK 17 or newer**
- One of:
  - **Docker Desktop** (runs everything, including MySQL, Prometheus and Grafana), or
  - **Maven 3.9+**, or **IntelliJ IDEA** (it bundles Maven)

The first build downloads the Spring dependencies from Maven Central, so it needs internet access.

## Run option A: Docker Compose (full stack, recommended for the demo)

```bash
docker compose up --build
```

| Service | URL |
|---|---|
| Gateway API | http://localhost:8080 |
| Live dashboard | http://localhost:8080/dashboard.html (admin / admin123) |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 (admin / admin). Dashboard: *Smart API Gateway* |
| MySQL | localhost:3306 (gateway / gateway, database `smartgateway`) |

Stop with `Ctrl+C`, then `docker compose down` (add `-v` to also delete the MySQL data).

## Run option B: Local, without Docker (embedded H2 database)

```bash
./run-local.sh          # macOS / Linux   (./stop-local.sh stops the backends)
run-local.bat           # Windows
```

Or by hand:

```bash
mvn -DskipTests package
java -jar user-service/target/user-service.jar
java -jar order-service/target/order-service.jar
java -jar gateway/target/gateway.jar
```

To use a local MySQL instead of H2, set `DB_URL`, `DB_USERNAME` and `DB_PASSWORD` before starting the gateway, e.g.
`DB_URL=jdbc:mysql://localhost:3306/smartgateway`.

## Run option C: IntelliJ IDEA

1. *File → Open* → select the root `pom.xml` → *Open as Project*.
2. Run `UserServiceApplication`, `OrderServiceApplication`, then `GatewayApplication`.

---

## Using the API

```bash
# 1. Log in (demo user) and keep the token
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"password123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

# 2. Call routed APIs through the gateway
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/1
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/orders/1001   # own order -> 200
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/orders/1002   # another user's -> 403

# 3. No token -> 401
curl -i http://localhost:8080/api/users/1
```

Rejected requests carry `Retry-After`, `X-Threat-Level` and `X-Threat-Action` headers and a JSON body.

## Demonstrating adaptive detection

**From the dashboard:** log in as admin and press *Simulate flood attack* or *Simulate injection probing*.
The simulated client moves LOW → MEDIUM/HIGH → CRITICAL and appears as blocked. *Unblock* lifts a block.

**Volumetric flood with curl:**

```bash
for i in $(seq 1 120); do
  curl -s -o /dev/null -w '%{http_code} ' -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/1
done; echo
```

Responses go from `200` to `429` once the client is rate-limited and then blocked.

**Credential stuffing:** send about 8 wrong passwords to `/auth/login` within a minute. The source IP is then blocked.

**Injection probing:** a few requests such as `/api/users/1%20union%20select%20password` raise the risk sharply. The client is blocked even though its request rate is low.

## Load testing with JMeter

The test plan `jmeter/smart-gateway-load-test.jmx` runs four client groups at once:
- 10 normal users
- a volumetric attacker (about 30 req/s)
- a credential-stuffing client
- an injection prober

Each group sends its own `X-Forwarded-For` address, so start the gateway with `TRUST_FORWARDED_HEADERS=true` for this test only:

```bash
TRUST_FORWARDED_HEADERS=true java -jar gateway/target/gateway.jar      # (plus the two backends)
jmeter -n -t jmeter/smart-gateway-load-test.jmx -Jduration=120 \
       -l jmeter/results/results.jtl -e -o jmeter/results/report
```

For Docker Compose, add `TRUST_FORWARDED_HEADERS: "true"` under the gateway's `environment:` section.
Open `jmeter/results/report/index.html`. Expected result: normal users keep receiving 200, while the three attacking groups are throttled and then receive 429.

## Monitoring

`/actuator/prometheus` exposes the following metrics.

| Metric | Meaning |
|---|---|
| `smartgateway_threat_decisions_total{scope,level,action}` | Decisions by IP / user scope, level and action |
| `smartgateway_threat_blocked_clients` | Clients currently blacklisted |
| `smartgateway_threat_tracked_clients` | Behaviour profiles in memory |
| `smartgateway_traffic_health_factor` | 1.0 = within capacity; lower values shrink all rate limits |
| `smartgateway_threat_evaluation_seconds` | Time spent scoring a request |
| `spring_cloud_gateway_requests_seconds` | Routed request latency (Spring Cloud Gateway) |

## Tests

```bash
mvn test
```

- `ThreatEngineTest` contains 14 deterministic tests that use a simulated clock: normal traffic, flood escalation, recovery after a block, escalating block durations, injection probing, credential stuffing, evidence decay, no 429 feedback, NAT tolerance, token bucket, global overload, eviction, unblocking and excluded paths.
- `GatewaySecurityIntegrationTest` and `CredentialStuffingIntegrationTest` start the real gateway and check login, 401, 403, roles, registration validation, the actuator endpoints, and blocking of repeated failed logins.

## Configuration

Every threat parameter lives under `smartgateway.threat` in `gateway/src/main/resources/application.yml`.
Important environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | demo value | HS256 key, at least 32 bytes. **Change it for any real use.** |
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | embedded H2 | Database connection |
| `USER_SERVICE_URL`, `ORDER_SERVICE_URL` | localhost:8081 / 8082 | Backend routes |
| `TRUST_FORWARDED_HEADERS` | `false` | Use `X-Forwarded-For` as the client IP (only behind a trusted proxy) |
| `ADMIN_PASSWORD`, `DEMO_PASSWORD` | admin123 / password123 | Seeded accounts (only used on first start) |
| `GATEWAY_PORT` | 8080 | Gateway port |

## Project structure

```text
smart-api-gateway/
├── pom.xml                          parent (Spring Boot 3.3.5, Spring Cloud 2023.0.3, Java 17)
├── gateway/                         Spring Cloud Gateway + security + threat detection
│   └── src/main/java/com/smartgateway/gateway/
│       ├── threat/                  ThreatEngine (framework-free), risk model, decisions
│       ├── filter/                  IpThreatWebFilter, ThreatDetectionGlobalFilter
│       ├── security/                SecurityConfig, JwtService
│       ├── auth/                    login / registration, user repository, seeding
│       ├── audit/                   security events + blacklist persistence (MySQL)
│       ├── metrics/                 Prometheus metrics
│       ├── admin/                   admin API + attack simulations for the dashboard
│       └── config/, support/
├── user-service/                    demo backend (port 8081)
├── order-service/                   demo backend with object-level authorisation (port 8082)
├── docker-compose.yml, Dockerfile   full stack: MySQL, services, Prometheus, Grafana
├── monitoring/                      Prometheus config, Grafana provisioning + dashboard
├── jmeter/                          load / attack test plan
├── postman/                         API collection
└── docs/                            architecture, PPT mapping, viva notes
```

## Troubleshooting

- **`release version 17 not supported`**: Maven is using an older JDK. Set `JAVA_HOME` to JDK 17 or newer.
- **Port already in use**: stop the other process, or set `GATEWAY_PORT`, `USER_SERVICE_PORT` or `ORDER_SERVICE_PORT`.
- **Routed calls return 503 / 504**: user-service and order-service are not running.
- **Everything returns 429 during testing**: your own IP was blocked (for example after a curl flood or repeated wrong passwords). Wait for the block to expire (60 s for a first offence). If the dashboard is already open, you can also press *Unblock*, because the admin API is never blocked. In local H2 mode, restarting the gateway also clears all blocks; in MySQL mode, blocks survive a restart.
- **Dependency download fails behind a proxy**: configure Maven's proxy in `~/.m2/settings.xml`.
