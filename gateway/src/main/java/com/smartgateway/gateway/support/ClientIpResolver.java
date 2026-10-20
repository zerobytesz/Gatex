package com.smartgateway.gateway.support;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;

/**
 * Resolves the client IP used as the IP-scope identity.
 * X-Forwarded-For is honoured only when explicitly enabled (i.e. when the gateway sits behind a trusted
 * reverse proxy); otherwise a client could spoof its identity by sending the header itself.
 */
@Component
public class ClientIpResolver {

    private final boolean trustForwardedHeaders;

    public ClientIpResolver(@Value("${smartgateway.trust-forwarded-headers:false}") boolean trustForwardedHeaders) {
        this.trustForwardedHeaders = trustForwardedHeaders;
    }

    public String resolve(ServerHttpRequest request) {
        if (trustForwardedHeaders) {
            String xff = request.getHeaders().getFirst("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        }
        InetSocketAddress remote = request.getRemoteAddress();
        if (remote == null) return "unknown";
        return remote.getAddress() != null ? remote.getAddress().getHostAddress() : remote.getHostString();
    }
}
