# Mapping from the Review-I presentation to the implementation

| Slide | Content in the PPT | Where it is implemented |
|---|---|---|
| 2 Problem statement | Unauthorized access and API abuse | JWT required on all routed APIs (`SecurityConfig`); BOLA protection in `order-service` |
| 2 | DDoS and credential stuffing | Rate / burst scoring, adaptive token bucket, failed-login evidence, IP blacklist (`ThreatEngine`, `IpThreatWebFilter`) |
| 2 | Static rules that fail to adapt | Limits depend on the threat level and on global traffic health (`ThreatEngine.evaluate`, `healthFactor`) |
| 2 | No real-time behavioural detection | Per-request risk score at IP and user scope, with decaying evidence |
| 3 OWASP focus | Broken authentication, BOLA, unrestricted resource consumption | JWT + BCrypt + failed-login detection; ownership check (403) counted as evidence; adaptive limits |
| 4 Objectives | Authenticate | `/auth/login`, `/auth/register`, `JwtService`, Spring Security resource server |
| 4 | Limit & Throttle | Adaptive token bucket; non-blocking throttle delays at MEDIUM / HIGH |
| 4 | Detect | Risk model: rate, burst, failures, suspicious paths, failed logins |
| 4 | Mitigate | Temporary blacklist with escalating duration, persisted in `client_blacklist` |
| 7 Research gap | Detection and response embedded in a lightweight Java gateway | Engine runs in-process inside Spring Cloud Gateway; no external security service |
| 8 Architecture | Client → gateway → auth → threat detection → rate limiter → backends | `IpThreatWebFilter` → Spring Security → `ThreatDetectionGlobalFilter` → routes |
| 9 Innovation | Adaptive defence: limits adjust to traffic health | `globalCapacityPerWindow`, `minHealthFactor`, health-factor gauge |
| 9 | Auto-throttling and ban of IPs | `IP` scope profiles and blacklist; `Retry-After` on 429 |
| 9 | Lightweight and modular, Java/Spring | Framework-free `ThreatEngine`, wired with Spring beans |
| 10 Methodology | Phase 3: gateway development (Spring Cloud Gateway) | `gateway` module |
| 10 | Phase 4: integrating the threat detection logic | `threat` + `filter` packages |
| 10 | Phase 5: testing (Postman / JMeter) | `postman/`, `jmeter/`, JUnit tests |
| 11 Technology stack | Java, Spring Boot | Spring Boot 3.3.5, Java 17 |
| 11 | Spring Cloud Gateway | Spring Cloud 2023.0.3 (`spring-cloud-starter-gateway`) |
| 11 | Spring Security, JWT | `spring-boot-starter-security`, `spring-boot-starter-oauth2-resource-server` (Nimbus JOSE, HS256) |
| 11 | MySQL (config / logs) | `app_users`, `security_events`, `client_blacklist` (MySQL 8.4 in Docker) |
| 11 | Prometheus, Grafana | Micrometer Prometheus registry; `monitoring/` provisioning and dashboard |
| 11 | IntelliJ, Maven, Docker, Postman | Maven multi-module project, `Dockerfile`, `docker-compose.yml`, Postman collection |
| 12 Expected results | Detection of simulated malicious traffic; mitigation without crashing | Dashboard simulations, JMeter plan, integration tests |
| 12 Future scope | ML anomaly detection, Kubernetes, Zero Trust | Not implemented. `ThreatEngine` is the extension point (see architecture.md) |
