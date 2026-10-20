package com.smartgateway.gateway.threat;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deterministic tests of the adaptive threat engine using a simulated clock. */
class ThreatEngineTest {

    private long now = 1_000_000L;
    private ThreatEngine engine(ThreatProperties p) { return new ThreatEngine(p, () -> now); }

    @Test
    void normalTrafficStaysLowAndIsAllowed() {
        ThreatEngine e = engine(new ThreatProperties());
        for (int i = 0; i < 300; i++) {          // 1 request/second for 5 minutes
            Decision d = e.evaluate("user:alice", "/api/users/1", Scope.USER);
            assertEquals(SecurityAction.ALLOW, d.action());
            assertEquals(ThreatLevel.LOW, d.level());
            now += 1000;
        }
    }

    @Test
    void floodEscalatesThroughLevelsAndIsBlocked() {
        ThreatEngine e = engine(new ThreatProperties());
        List<ThreatLevel> seen = new ArrayList<>();
        Decision d = null;
        for (int i = 0; i < 200; i++) {          // 50 requests/second
            d = e.evaluate("user:mallory", "/api/users/1", Scope.USER);
            if (seen.isEmpty() || seen.get(seen.size() - 1) != d.level()) seen.add(d.level());
            if (d.action() == SecurityAction.BLOCK) break;
            now += 20;
        }
        assertEquals(SecurityAction.BLOCK, d.action());
        assertTrue(d.newlyBlocked());
        assertEquals(ThreatLevel.LOW, seen.get(0));
        assertTrue(seen.contains(ThreatLevel.MEDIUM) || seen.contains(ThreatLevel.HIGH));
        assertTrue(e.isBlocked("user:mallory"));
    }

    @Test
    void blockedRequestsDoNotExtendTheBlockAndClientRecovers() {
        ThreatProperties p = new ThreatProperties();
        ThreatEngine e = engine(p);
        while (e.evaluate("user:carol", "/api/users/1", Scope.USER).action() != SecurityAction.BLOCK) now += 10;
        long blockedAt = now;
        // keep polling every 2 s while blocked: must not extend the block
        while (now < blockedAt + p.getBlockSeconds() * 1000L) {
            assertEquals(SecurityAction.BLOCK, e.evaluate("user:carol", "/api/users/1", Scope.USER).action());
            now += 2000;
        }
        now += 1000;
        Decision after = e.evaluate("user:carol", "/api/users/1", Scope.USER);
        assertFalse(after.denied(), "client must regain access when the block expires");
    }

    @Test
    void repeatOffendersGetLongerBlocks() {
        ThreatProperties p = new ThreatProperties();
        ThreatEngine e = engine(p);
        Decision first = null, second = null;
        while ((first = e.evaluate("user:x", "/api/users/1", Scope.USER)).action() != SecurityAction.BLOCK) now += 10;
        now += p.getBlockSeconds() * 1000L + 1000;
        while ((second = e.evaluate("user:x", "/api/users/1", Scope.USER)).action() != SecurityAction.BLOCK) now += 10;
        assertTrue(second.retryAfterSeconds() >= 2 * first.retryAfterSeconds() - 1,
                "second block (" + second.retryAfterSeconds() + "s) should be ~2x the first (" + first.retryAfterSeconds() + "s)");
    }

    @Test
    void injectionProbingIsBlockedAtLowRequestRate() {
        ThreatEngine e = engine(new ThreatProperties());
        String[] payloads = {"/api/users/1%20union%20select%20password", "/api/users/..%2f..%2fetc%2fpasswd",
                "/api/users/%3Cscript%3Ealert(1)", "/api/orders/1'%20or%20'1'='1"};
        Decision d = null;
        for (int i = 0; i < 12 && (d == null || d.action() != SecurityAction.BLOCK); i++) {
            d = e.evaluate("user:probe", payloads[i % payloads.length], Scope.USER);
            e.recordOutcome("user:probe", payloads[i % payloads.length], 400);
            now += 2000;                           // only 0.5 requests per second
        }
        assertEquals(SecurityAction.BLOCK, d.action());
    }

    @Test
    void credentialStuffingFromOneIpIsBlocked() {
        ThreatEngine e = engine(new ThreatProperties());
        Decision d = null;
        for (int i = 0; i < 20; i++) {
            d = e.evaluate("ip:203.0.113.9", "/auth/login", Scope.IP);
            if (d.action() == SecurityAction.BLOCK) break;
            e.recordOutcome("ip:203.0.113.9", "/auth/login", 401);
            now += 1000;
        }
        assertEquals(SecurityAction.BLOCK, d.action());
    }

    @Test
    void occasionalUserMistakesDecayAway() {
        ThreatEngine e = engine(new ThreatProperties());
        for (int i = 0; i < 3; i++) {             // three 404s in a row
            e.evaluate("user:bob", "/api/users/999", Scope.USER);
            e.recordOutcome("user:bob", "/api/users/999", 404);
        }
        now += 5 * 60_000;                         // five minutes later
        Decision d = e.evaluate("user:bob", "/api/users/1", Scope.USER);
        assertEquals(ThreatLevel.LOW, d.level());
        assertTrue(d.risk() < 5);
    }

    @Test
    void gatewayGenerated429DoesNotFeedBackIntoTheScore() {
        ThreatEngine e = engine(new ThreatProperties());
        e.evaluate("user:dave", "/api/users/1", Scope.USER);
        for (int i = 0; i < 50; i++) e.recordOutcome("user:dave", "/api/users/1", 429);
        assertEquals(0, e.evaluate("user:dave", "/api/users/1", Scope.USER).risk());
    }

    @Test
    void ipScopeToleratesManyUsersBehindOneNat() {
        ThreatEngine e = engine(new ThreatProperties());
        for (int i = 0; i < 600; i++) {            // 30 users x 0.5 req/s = 15 req/s from one IP for 40 s
            Decision d = e.evaluate("ip:198.51.100.1", "/api/users/1", Scope.IP);
            assertFalse(d.denied());
            now += 66;
        }
    }

    @Test
    void tokenBucketRateLimitsSustainedExcessBeforeBlocking() {
        ThreatProperties p = new ThreatProperties();
        p.setCriticalThreshold(101);               // disable blocking to observe the bucket alone
        ThreatEngine e = engine(p);
        int limited = 0;
        for (int i = 0; i < 400; i++) {            // 40 req/s for 10 s
            if (e.evaluate("user:eve", "/api/users/1", Scope.USER).action() == SecurityAction.RATE_LIMITED) limited++;
            now += 25;
        }
        assertTrue(limited > 0, "sustained excess must hit the adaptive token bucket");
    }

    @Test
    void globalOverloadShrinksHealthFactor() {
        ThreatProperties p = new ThreatProperties();
        p.setGlobalCapacityPerWindow(100);
        ThreatEngine e = engine(p);
        assertEquals(1.0, e.healthFactor(), 1e-9);
        for (int i = 0; i < 400; i++) e.observeGlobal();
        assertTrue(e.healthFactor() < 1.0);
        assertTrue(e.healthFactor() >= p.getMinHealthFactor());
    }

    @Test
    void idleProfilesAreEvictedButBlockedOnesAreKept() {
        ThreatProperties p = new ThreatProperties();
        p.setIdleEvictSeconds(60);
        ThreatEngine e = engine(p);
        for (int i = 0; i < 1000; i++) e.evaluate("ip:rot-" + i, "/api/users/1", Scope.IP);
        e.restoreBlock("ip:bad", now + 3_600_000, 1);
        now += 120_000;
        e.evictIdle();
        assertEquals(1, e.trackedClients());
        assertTrue(e.isBlocked("ip:bad"));
    }

    @Test
    void unblockRestoresAccess() {
        ThreatEngine e = engine(new ThreatProperties());
        while (e.evaluate("user:z", "/api/users/1", Scope.USER).action() != SecurityAction.BLOCK) now += 10;
        assertTrue(e.unblock("user:z"));
        assertFalse(e.evaluate("user:z", "/api/users/1", Scope.USER).denied());
    }

    @Test
    void excludedPathsAreRecognised() {
        ThreatEngine e = engine(new ThreatProperties());
        assertTrue(e.isExcluded("/actuator/prometheus"));
        assertTrue(e.isExcluded("/dashboard.html"));
        assertTrue(e.isExcluded("/"));
        assertFalse(e.isExcluded("/api/users/1"));
        assertFalse(e.isExcluded("/auth/login"));
    }
}
