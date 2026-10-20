package com.smartgateway.gateway.metrics;

import com.smartgateway.gateway.threat.Decision;
import com.smartgateway.gateway.threat.Scope;
import com.smartgateway.gateway.threat.ThreatEngine;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Prometheus metrics (exposed at /actuator/prometheus):
 *   smartgateway_threat_decisions_total{scope,level,action}
 *   smartgateway_threat_blocked_clients, smartgateway_threat_tracked_clients
 *   smartgateway_traffic_health_factor, smartgateway_traffic_requests_in_window
 *   smartgateway_threat_evaluation_seconds (time spent scoring a request)
 */
@Component
public class ThreatMetrics {

    private final MeterRegistry registry;
    private final Timer evaluation;

    public ThreatMetrics(MeterRegistry registry, ThreatEngine engine) {
        this.registry = registry;
        Gauge.builder("smartgateway.threat.blocked.clients", engine, ThreatEngine::blockedClients)
                .description("Clients currently blacklisted").register(registry);
        Gauge.builder("smartgateway.threat.tracked.clients", engine, ThreatEngine::trackedClients)
                .description("Client behaviour profiles held in memory").register(registry);
        Gauge.builder("smartgateway.traffic.health.factor", engine, ThreatEngine::healthFactor)
                .description("1.0 = within capacity; lower values shrink all rate limits").register(registry);
        Gauge.builder("smartgateway.traffic.requests.in.window", engine, ThreatEngine::globalRequestsInWindow)
                .description("Requests observed gateway-wide in the sliding window").register(registry);
        this.evaluation = Timer.builder("smartgateway.threat.evaluation")
                .description("Time spent evaluating a request in the threat engine").register(registry);
    }

    public void record(Scope scope, Decision d, long evaluationNanos) {
        registry.counter("smartgateway.threat.decisions",
                "scope", scope.name(), "level", d.level().name(), "action", d.action().name()).increment();
        evaluation.record(evaluationNanos, TimeUnit.NANOSECONDS);
    }
}
