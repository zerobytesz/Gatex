package com.smartgateway.gateway.filter;

import com.smartgateway.gateway.metrics.ThreatMetrics;
import com.smartgateway.gateway.support.Responses;
import com.smartgateway.gateway.threat.Decision;
import com.smartgateway.gateway.threat.Scope;
import com.smartgateway.gateway.threat.ThreatEngine;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Adaptive threat detection for routed API traffic, applied per authenticated user (JWT subject).
 * Identity comes from the verified token, never from a client-supplied header, so it cannot be rotated
 * to evade detection. The verified identity is passed to backends as X-Authenticated-User / X-User-Role.
 */
@Component
public class ThreatDetectionGlobalFilter implements GlobalFilter, Ordered {

    private final ThreatEngine engine;
    private final ThreatMetrics metrics;

    public ThreatDetectionGlobalFilter(ThreatEngine engine, ThreatMetrics metrics) {
        this.engine = engine;
        this.metrics = metrics;
    }

    @Override
    public int getOrder() { return 100; }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Map to Optional first: evaluate(...) completes empty (Mono<Void>), so switchIfEmpty must not be used
        // after it, or the request would be forwarded twice.
        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(auth -> auth.isPresent() ? evaluate(exchange, chain, auth.get()) : chain.filter(exchange));
    }

    private Mono<Void> evaluate(ServerWebExchange exchange, GatewayFilterChain chain, JwtAuthenticationToken auth) {
        String user = auth.getName();
        String key = "user:" + user;
        String target = IpThreatWebFilter.pathAndQuery(exchange.getRequest());

        long t0 = System.nanoTime();
        Decision d = engine.evaluate(key, target, Scope.USER);
        metrics.record(Scope.USER, d, System.nanoTime() - t0);
        exchange.getAttributes().put(ExchangeAttributes.USER_KEY, key);
        exchange.getAttributes().put(ExchangeAttributes.USER_DECISION, d);

        if (d.denied()) return Responses.reject(exchange, d);

        List<String> roles = auth.getToken().getClaimAsStringList("roles");
        String role = roles == null || roles.isEmpty() ? "USER" : roles.get(0);
        ServerWebExchange forwarded = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.remove("X-Client-Id");
                    h.set("X-Authenticated-User", user);
                    h.set("X-User-Role", role);
                }))
                .build();

        String path = exchange.getRequest().getPath().value();
        Mono<Void> proceed = chain.filter(forwarded)
                .doFinally(signal -> engine.recordOutcome(key, path, Responses.status(forwarded)));
        long delay = engine.properties().throttleDelayMs(d.action());
        return delay > 0 ? Mono.delay(Duration.ofMillis(delay)).then(proceed) : proceed;
    }
}
