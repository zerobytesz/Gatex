package com.smartgateway.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Smart API Gateway with Adaptive Threat Detection.
 *
 * Request pipeline:
 *   Client -> IpThreatWebFilter (IP blacklist, IP-scope risk, global traffic health)
 *          -> Spring Security (JWT authentication / authorisation)
 *          -> ThreatDetectionGlobalFilter (user-scope risk, adaptive rate limit, throttle / block)
 *          -> Spring Cloud Gateway routing -> user-service / order-service
 *          -> audit log (MySQL) + Prometheus metrics + live dashboard
 */
@SpringBootApplication
@EnableScheduling
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
