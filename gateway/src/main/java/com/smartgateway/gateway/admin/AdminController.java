package com.smartgateway.gateway.admin;

import com.smartgateway.gateway.audit.SecurityEvent;
import com.smartgateway.gateway.audit.SecurityEventService;
import com.smartgateway.gateway.metrics.ThreatMetrics;
import com.smartgateway.gateway.threat.Decision;
import com.smartgateway.gateway.threat.ProfileView;
import com.smartgateway.gateway.threat.Scope;
import com.smartgateway.gateway.threat.ThreatEngine;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin API used by the live dashboard (requires the ADMIN role).
 * The demo endpoints drive simulated clients through the real threat engine so the adaptive behaviour can
 * be shown without external tools; simulated clients are prefixed "sim:" and are audited like real traffic.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final String[] INJECTION_PATHS = {
            "/api/users/1%20union%20select%20password%20from%20app_users",
            "/api/users/..%2f..%2fetc%2fpasswd",
            "/api/users/%3Cscript%3Ealert(1)%3C/script%3E",
            "/api/orders/1001'%20or%20'1'='1"};

    private final ThreatEngine engine;
    private final SecurityEventService audit;
    private final ThreatMetrics metrics;

    public AdminController(ThreatEngine engine, SecurityEventService audit, ThreatMetrics metrics) {
        this.engine = engine;
        this.audit = audit;
        this.metrics = metrics;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview() {
        List<ProfileView> profiles = engine.snapshot(100);
        long low = profiles.stream().filter(p -> p.level().name().equals("LOW")).count();
        long medium = profiles.stream().filter(p -> p.level().name().equals("MEDIUM")).count();
        long high = profiles.stream().filter(p -> p.level().name().equals("HIGH")).count();
        long critical = profiles.stream().filter(p -> p.level().name().equals("CRITICAL")).count();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timestamp", System.currentTimeMillis());
        m.put("trackedClients", engine.trackedClients());
        m.put("blockedClients", engine.blockedClients());
        m.put("low", low);
        m.put("medium", medium);
        m.put("high", high);
        m.put("critical", critical);
        m.put("healthFactor", engine.healthFactor());
        m.put("requestsInWindow", engine.globalRequestsInWindow());
        m.put("windowSeconds", engine.properties().getWindowSeconds());
        m.put("totalEvents", audit.totalEvents());
        m.put("deniedEvents", audit.deniedEvents());
        m.put("profiles", profiles);
        return m;
    }

    @GetMapping("/events")
    public List<SecurityEvent> events(@RequestParam(defaultValue = "50") int limit) {
        return audit.recent(Math.max(1, Math.min(limit, 500)));
    }

    @PostMapping("/unblock")
    public ResponseEntity<Map<String, Object>> unblock(@RequestParam String key) {
        boolean known = engine.unblock(key);
        audit.removeBlock(key);
        return ResponseEntity.ok(Map.of("key", key, "unblocked", known));
    }

    /** Simulates a volumetric attack: ~30 requests/second for 8 seconds from "sim:attacker". */
    @PostMapping("/demo/attack")
    public Map<String, Object> demoAttack() {
        String key = "sim:attacker";
        engine.reset(key);
        Flux.interval(Duration.ofMillis(33)).take(240)
                .doOnNext(i -> simulate(key, "/api/users/1", 200))
                .subscribe();
        return Map.of("message", "Volumetric attack simulation started", "client", key,
                "expected", "LOW -> MEDIUM/HIGH (throttled) -> CRITICAL (blocked, 429)");
    }

    /** Simulates low-rate injection probing (one request every 1.5 s) from "sim:injector". */
    @PostMapping("/demo/injection")
    public Map<String, Object> demoInjection() {
        String key = "sim:injector";
        engine.reset(key);
        Flux.interval(Duration.ofMillis(1500)).take(8)
                .doOnNext(i -> simulate(key, INJECTION_PATHS[(int) (i % INJECTION_PATHS.length)], 400))
                .subscribe();
        return Map.of("message", "Injection probing simulation started", "client", key,
                "expected", "blocked after a few payloads although the request rate is low");
    }

    /** One well-behaved request from "sim:normal-user". */
    @PostMapping("/demo/normal")
    public Map<String, Object> demoNormal() {
        Decision d = simulate("sim:normal-user", "/api/users/1", 200);
        return Map.of("client", "sim:normal-user", "level", d.level(), "action", d.action(), "risk", d.risk());
    }

    @PostMapping("/demo/reset")
    public Map<String, Object> demoReset() {
        for (String k : List.of("sim:attacker", "sim:injector", "sim:normal-user")) {
            engine.reset(k);
            audit.removeBlock(k);
        }
        return Map.of("message", "Simulated clients reset");
    }

    private Decision simulate(String key, String path, int backendStatus) {
        long t0 = System.nanoTime();
        Decision d = engine.evaluate(key, path, Scope.USER);
        metrics.record(Scope.USER, d, System.nanoTime() - t0);
        int status = d.denied() ? 429 : backendStatus;
        engine.recordOutcome(key, path, status);
        audit.record(new SecurityEvent(System.currentTimeMillis(), key, "simulated", "GET", path, status,
                d.risk(), d.level().name(), d.action().name()));
        return d;
    }
}
