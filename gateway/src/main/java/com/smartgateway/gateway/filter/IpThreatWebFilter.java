package com.smartgateway.gateway.filter;

import com.smartgateway.gateway.audit.SecurityEvent;
import com.smartgateway.gateway.audit.SecurityEventService;
import com.smartgateway.gateway.metrics.ThreatMetrics;
import com.smartgateway.gateway.support.ClientIpResolver;
import com.smartgateway.gateway.support.Responses;
import com.smartgateway.gateway.threat.Decision;
import com.smartgateway.gateway.threat.Scope;
import com.smartgateway.gateway.threat.ThreatEngine;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * First line of defence, executed before Spring Security (order -200 vs. -100):
 * <ul>
 *   <li>rejects blacklisted IPs immediately with 429,</li>
 *   <li>scores every request at IP scope (so unauthenticated abuse such as credential stuffing and token
 *       guessing is visible), and counts it toward global traffic health,</li>
 *   <li>after the response, feeds the HTTP status back as evidence and writes one audit event that
 *       combines the IP-scope and user-scope decisions.</li>
 * </ul>
 */
@Component
public class IpThreatWebFilter implements WebFilter, Ordered {

    private final ThreatEngine engine;
    private final ClientIpResolver ipResolver;
    private final SecurityEventService audit;
    private final ThreatMetrics metrics;

    public IpThreatWebFilter(ThreatEngine engine, ClientIpResolver ipResolver, SecurityEventService audit, ThreatMetrics metrics) {
        this.engine = engine;
        this.ipResolver = ipResolver;
        this.audit = audit;
        this.metrics = metrics;
    }

    @Override
    public int getOrder() { return -200; }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();
        String path = req.getPath().value();
        if (engine.isExcluded(path)) return chain.filter(exchange);

        String ip = ipResolver.resolve(req);
        String key = "ip:" + ip;
        String target = pathAndQuery(req);
        exchange.getAttributes().put(ExchangeAttributes.CLIENT_IP, ip);

        engine.observeGlobal();
        long t0 = System.nanoTime();
        Decision ipDecision = engine.evaluate(key, target, Scope.IP);
        metrics.record(Scope.IP, ipDecision, System.nanoTime() - t0);

        if (ipDecision.denied()) {
            audit.record(event(exchange, key, ip, target, 429, ipDecision));
            return Responses.reject(exchange, ipDecision);
        }

        Mono<Void> proceed = chain.filter(exchange).doFinally(signal -> {
            int status = Responses.status(exchange);
            engine.recordOutcome(key, path, status);
            Decision userDecision = exchange.getAttribute(ExchangeAttributes.USER_DECISION);
            String userKey = exchange.getAttribute(ExchangeAttributes.USER_KEY);
            Decision combined = Decision.mostSevere(ipDecision, userDecision);
            audit.record(event(exchange, userKey != null ? userKey : key, ip, target, status, combined));
        });
        long delay = engine.properties().throttleDelayMs(ipDecision.action());
        return delay > 0 ? Mono.delay(Duration.ofMillis(delay)).then(proceed) : proceed;
    }

    static String pathAndQuery(ServerHttpRequest req) {
        String raw = req.getURI().getRawPath();
        String q = req.getURI().getRawQuery();
        return q == null ? raw : raw + "?" + q;
    }

    private static SecurityEvent event(ServerWebExchange ex, String key, String ip, String target, int status, Decision d) {
        return new SecurityEvent(System.currentTimeMillis(), key, ip, ex.getRequest().getMethod().name(), target,
                status, d.risk(), d.level().name(), d.action().name());
    }
}
