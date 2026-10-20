package com.smartgateway.gateway.support;

import com.smartgateway.gateway.threat.Decision;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/** Writes the JSON 429 response used for rate-limited and blocked requests. */
public final class Responses {

    private Responses() { }

    public static Mono<Void> reject(ServerWebExchange exchange, Decision d) {
        ServerHttpResponse res = exchange.getResponse();
        res.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        res.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        res.getHeaders().set("Retry-After", String.valueOf(d.retryAfterSeconds()));
        res.getHeaders().set("X-Threat-Level", d.level().name());
        res.getHeaders().set("X-Threat-Action", d.action().name());
        String error = d.action().name().equals("BLOCK") ? "Client temporarily blocked" : "Rate limit exceeded";
        String body = "{\"error\":\"" + error + "\",\"threatLevel\":\"" + d.level() + "\",\"risk\":" + d.risk()
                + ",\"action\":\"" + d.action() + "\",\"retryAfterSeconds\":" + d.retryAfterSeconds() + "}";
        DataBuffer buffer = res.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return res.writeWith(Mono.just(buffer));
    }

    public static int status(ServerWebExchange exchange) {
        var code = exchange.getResponse().getStatusCode();
        return code == null ? 200 : code.value();
    }
}
