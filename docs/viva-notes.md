# Viva notes

**What problem does the project solve?**
Ordinary gateways authenticate and route requests, and apply fixed rate limits. They do not notice when a client starts behaving abusively, and they do not react on their own. This gateway scores each client's behaviour in real time and moves it through allow, throttle, rate-limit and block automatically.

**Why Spring Cloud Gateway?**
It is a non-blocking (WebFlux / Netty) gateway with routing, filters and metrics built in. The threat logic plugs in as a `GlobalFilter` plus a `WebFilter`.

**How does authentication work?**
`/auth/login` checks the BCrypt hash and issues an HS256 JWT containing `sub`, `roles`, `iss` and `exp`. Spring Security's resource server validates the token on every request. No server-side session is kept.

**What makes it adaptive?**
Two things.
- The limits depend on the client's threat level: the token bucket shrinks from 40/10 per s down to 8/1 per s, and the client is blocked at CRITICAL.
- When total traffic exceeds the gateway's capacity, all buckets refill more slowly (the traffic health factor).

**What behaviour is detected?**
Floods and bursts, repeated failures (404 / 403 enumeration, BOLA attempts), injection, XSS, traversal and admin probing in the URL, and failed logins (credential stuffing).

**Is it machine learning?**
No. It is a transparent, explainable scoring model with configurable weights. ML is future work, and the engine is designed so that a model can add a term to the score.

**Why two scopes (IP and user)?**
- The IP scope sees unauthenticated abuse, such as credential stuffing and token guessing.
- The user scope follows an authenticated client even when it changes IP.
- IP limits are 5× higher so that many users behind one NAT are not punished.

**What happens at CRITICAL?**
The client receives 429 with a `Retry-After` header for 60 s. Repeat offences double the duration, up to 16×. Requests made while blocked are not counted, so the block always ends. Blocks are stored in MySQL and survive a restart.

**How was it tested?**
- 14 JUnit tests of the engine with a simulated clock
- Spring Boot integration tests
- a Postman collection
- a JMeter plan with normal users, a flood, credential stuffing and injection probing
- dashboard simulations
