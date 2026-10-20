package com.smartgateway.gateway.threat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Adaptive, behaviour-based threat engine embedded in the API gateway.
 *
 * <p>For every client key (an authenticated user or a client IP) the engine keeps a sliding request window
 * and decaying evidence counters (failed responses, suspicious request paths, failed logins, burst points).
 * These are combined into a bounded risk score R in [0,100]:</p>
 *
 * <pre>
 *   R = min(100, min(Crate, w_rate * max(0, n - L))      // excess requests in the window
 *              + min(Cburst, B)                           // accumulated burst points
 *              + min(Cfail, w_fail * F)                   // failed (4xx/5xx) responses
 *              + min(Csusp, w_susp * S)                   // suspicious paths (injection / traversal / admin probing)
 *              + min(Clogin, w_login * G))                // failed logins
 * </pre>
 *
 * <p>where B, F, S and G decay as exp(-dt / tau). The risk selects a threat level (LOW / MEDIUM / HIGH /
 * CRITICAL) and the level selects the mitigation: an adaptive token bucket whose capacity and refill rate
 * shrink as the level rises (and as global traffic exceeds capacity), a non-blocking throttling delay, and at
 * CRITICAL a temporary blacklist whose duration doubles for repeat offenders. Requests received while blocked
 * are rejected without being counted, so a blocked client always regains access when the block expires.</p>
 *
 * <p>The engine has no framework dependencies and takes an injectable clock, which makes it deterministic
 * under test and reusable outside Spring.</p>
 */
public final class ThreatEngine {

    private final ThreatProperties p;
    private final LongSupplier clock;
    private final Map<String, ClientProfile> profiles = new ConcurrentHashMap<>();
    private volatile BlockListener blockListener = (k, u, o, r) -> { };

    // global traffic: one counter per second over the observation window (ring buffer)
    private final long[] secondStamp;
    private final long[] secondCount;

    public ThreatEngine(ThreatProperties properties, LongSupplier clock) {
        this.p = properties;
        this.clock = clock;
        this.secondStamp = new long[Math.max(1, properties.getWindowSeconds())];
        this.secondCount = new long[secondStamp.length];
    }

    public void setBlockListener(BlockListener listener) {
        this.blockListener = listener == null ? (k, u, o, r) -> { } : listener;
    }

    public ThreatProperties properties() { return p; }

    // ------------------------------------------------------------------ request evaluation

    /**
     * Evaluates one incoming request for the given client key and returns the mitigation to apply.
     * Call once per request per scope, before forwarding the request.
     */
    public Decision evaluate(String key, String pathAndQuery, Scope scope) {
        long now = clock.getAsLong();
        ClientProfile c = profiles.computeIfAbsent(key, k -> new ClientProfile(k, scope, now));
        synchronized (c) {
            c.lastSeen = now;
            if (now < c.blockedUntil) {
                return new Decision(SecurityAction.BLOCK, ThreatLevel.CRITICAL, 100, c.window.size(),
                        secondsUntil(c.blockedUntil, now), false);
            }
            decay(c, now);
            slide(c, now);
            c.window.addLast(now);

            String suspicious = matchSuspicious(pathAndQuery);
            if (suspicious != null) {
                c.suspicious += 1;
                c.lastReason = "suspicious pattern '" + suspicious + "'";
            }
            int n = c.window.size();
            int limit = limit(scope);
            if (n > limit) {
                c.burst += Math.min(20, n - limit);
                c.lastReason = "request rate " + n + " in " + p.getWindowSeconds() + "s window (limit " + limit + ")";
            }
            int risk = risk(c, n, limit);
            ThreatLevel level = levelOf(risk);
            c.lastRisk = risk;
            c.level = level;

            if (level == ThreatLevel.CRITICAL) {
                long duration = p.getBlockSeconds() * 1000L * (1L << Math.min(p.getMaxBlockEscalation(), c.offences));
                c.offences++;
                c.blockedUntil = now + duration;
                c.window.clear();
                c.tokens = -1;
                String reason = c.lastReason.isEmpty() ? "risk " + risk : c.lastReason;
                blockListener.onBlocked(key, c.blockedUntil, c.offences, reason);
                return new Decision(SecurityAction.BLOCK, level, risk, n, secondsUntil(c.blockedUntil, now), true);
            }

            // adaptive token bucket: capacity and refill depend on the threat level and on global traffic health
            double mult = scope == Scope.IP ? p.getIpLimitMultiplier() : 1;
            double cap = p.bucketCapacity(level) * mult;
            double rate = p.bucketRefillPerSecond(level) * mult * healthFactor(now);
            if (c.tokens < 0) c.tokens = cap;
            c.tokens = Math.min(cap, c.tokens + (now - c.lastRefill) / 1000.0 * rate);
            c.lastRefill = now;
            if (c.tokens < 1) {
                long retry = rate <= 0 ? 1 : (long) Math.ceil((1 - c.tokens) / rate);
                return new Decision(SecurityAction.RATE_LIMITED, level, risk, n, Math.max(1, retry), false);
            }
            c.tokens -= 1;
            SecurityAction action = switch (level) {
                case LOW -> SecurityAction.ALLOW;
                case MEDIUM -> SecurityAction.THROTTLE;
                default -> SecurityAction.STRONG_THROTTLE;
            };
            return new Decision(action, level, risk, n, 0, false);
        }
    }

    /**
     * Records the HTTP status returned for a request of this client. Failed logins (401 on the login path)
     * and other client/server errors become evidence; 429 responses produced by the gateway itself are ignored
     * so that mitigation never feeds back into the score.
     */
    public void recordOutcome(String key, String path, int status) {
        ClientProfile c = profiles.get(key);
        if (c == null || status < 400 || status == 429) return;
        long now = clock.getAsLong();
        synchronized (c) {
            decay(c, now);
            if (status == 401 && path != null && path.startsWith(p.getLoginPath())) {
                c.failedLogins += 1;
                c.lastReason = "failed login";
            } else {
                c.failures += 1;
                c.lastReason = "HTTP " + status + " response";
            }
        }
    }

    /** Counts one request toward global traffic health (call once per incoming request). */
    public void observeGlobal() {
        long sec = clock.getAsLong() / 1000;
        int i = (int) (sec % secondStamp.length);
        synchronized (secondStamp) {
            if (secondStamp[i] != sec) { secondStamp[i] = sec; secondCount[i] = 0; }
            secondCount[i]++;
        }
    }

    /** Requests observed gateway-wide in the current window. */
    public long globalRequestsInWindow() {
        long sec = clock.getAsLong() / 1000;
        long total = 0;
        synchronized (secondStamp) {
            for (int i = 0; i < secondStamp.length; i++) if (sec - secondStamp[i] < secondStamp.length) total += secondCount[i];
        }
        return total;
    }

    /** 1.0 while traffic is within capacity; shrinks proportionally (down to minHealthFactor) under overload. */
    public double healthFactor() { return healthFactor(clock.getAsLong()); }

    private double healthFactor(long now) {
        long g = globalRequestsInWindow();
        if (g <= p.getGlobalCapacityPerWindow()) return 1.0;
        return Math.max(p.getMinHealthFactor(), (double) p.getGlobalCapacityPerWindow() / g);
    }

    // ------------------------------------------------------------------ administration

    public boolean isBlocked(String key) {
        ClientProfile c = profiles.get(key);
        return c != null && clock.getAsLong() < c.blockedUntil;
    }

    /** Restores a persisted blacklist entry (e.g. after a restart). */
    public void restoreBlock(String key, long blockedUntil, int offences) {
        Scope scope = key.startsWith("ip:") ? Scope.IP : Scope.USER;
        ClientProfile c = profiles.computeIfAbsent(key, k -> new ClientProfile(k, scope, clock.getAsLong()));
        synchronized (c) {
            c.blockedUntil = Math.max(c.blockedUntil, blockedUntil);
            c.offences = Math.max(c.offences, offences);
            c.level = ThreatLevel.CRITICAL;
            c.lastRisk = 100;
            c.lastReason = "restored from blacklist";
        }
    }

    /** Lifts a block and clears the client's evidence. Returns false if the key is unknown. */
    public boolean unblock(String key) {
        ClientProfile c = profiles.get(key);
        if (c == null) return false;
        synchronized (c) {
            c.blockedUntil = 0;
            c.failures = c.suspicious = c.failedLogins = c.burst = 0;
            c.window.clear();
            c.tokens = -1;
            c.level = ThreatLevel.LOW;
            c.lastRisk = 0;
            c.lastReason = "unblocked by administrator";
        }
        return true;
    }

    public void reset(String key) { profiles.remove(key); }

    /** Removes idle, unblocked profiles and enforces the profile cap (protects memory against identity rotation). */
    public int evictIdle() {
        long now = clock.getAsLong();
        long idle = p.getIdleEvictSeconds() * 1000L;
        int before = profiles.size();
        profiles.values().removeIf(c -> now >= c.blockedUntil && now - c.lastSeen > idle);
        if (profiles.size() > p.getMaxProfiles()) {
            List<ClientProfile> victims = new ArrayList<>(profiles.values());
            victims.removeIf(c -> now < c.blockedUntil);
            victims.sort(Comparator.comparingLong(c -> c.lastSeen));
            int excess = profiles.size() - p.getMaxProfiles();
            for (int i = 0; i < excess && i < victims.size(); i++) profiles.remove(victims.get(i).key);
        }
        return before - profiles.size();
    }

    public int trackedClients() { return profiles.size(); }

    public int blockedClients() {
        long now = clock.getAsLong();
        int n = 0;
        for (ClientProfile c : profiles.values()) if (now < c.blockedUntil) n++;
        return n;
    }

    /** Current (time-decayed) view of all profiles, highest risk first. Does not modify state. */
    public List<ProfileView> snapshot(int limit) {
        long now = clock.getAsLong();
        List<ProfileView> out = new ArrayList<>();
        for (ClientProfile c : profiles.values()) {
            synchronized (c) {
                boolean blocked = now < c.blockedUntil;
                int inWindow = 0;
                for (Long t : c.window) if (now - t <= p.getWindowSeconds() * 1000L) inWindow++;
                int risk = blocked ? 100 : currentRisk(c, now, inWindow);
                ThreatLevel level = blocked ? ThreatLevel.CRITICAL : levelOf(risk);
                out.add(new ProfileView(c.key, level, risk, inWindow, blocked, c.blockedUntil, c.offences, c.lastSeen, c.lastReason));
            }
        }
        out.sort(Comparator.comparingInt(ProfileView::risk).reversed().thenComparing(Comparator.comparingLong(ProfileView::lastSeen).reversed()));
        return out.size() > limit ? out.subList(0, limit) : out;
    }

    // ------------------------------------------------------------------ internals

    public ThreatLevel levelOf(int risk) {
        if (risk >= p.getCriticalThreshold()) return ThreatLevel.CRITICAL;
        if (risk >= p.getHighThreshold()) return ThreatLevel.HIGH;
        if (risk >= p.getMediumThreshold()) return ThreatLevel.MEDIUM;
        return ThreatLevel.LOW;
    }

    private int limit(Scope scope) {
        return scope == Scope.IP ? p.getNormalLimit() * p.getIpLimitMultiplier() : p.getNormalLimit();
    }

    private int risk(ClientProfile c, int n, int limit) {
        double r = Math.min(p.getRateCap(), p.getRateWeight() * Math.max(0, n - limit))
                + Math.min(p.getBurstCap(), c.burst)
                + Math.min(p.getFailureCap(), p.getFailureWeight() * c.failures)
                + Math.min(p.getSuspiciousCap(), p.getSuspiciousWeight() * c.suspicious)
                + Math.min(p.getFailedLoginCap(), p.getFailedLoginWeight() * c.failedLogins);
        return (int) Math.min(100, Math.round(r));
    }

    private int currentRisk(ClientProfile c, long now, int n) {
        double f = decayFactor(now - c.lastDecay);
        int limit = limit(c.scope);
        double r = Math.min(p.getRateCap(), p.getRateWeight() * Math.max(0, n - limit))
                + Math.min(p.getBurstCap(), c.burst * f)
                + Math.min(p.getFailureCap(), p.getFailureWeight() * c.failures * f)
                + Math.min(p.getSuspiciousCap(), p.getSuspiciousWeight() * c.suspicious * f)
                + Math.min(p.getFailedLoginCap(), p.getFailedLoginWeight() * c.failedLogins * f);
        return (int) Math.min(100, Math.round(r));
    }

    private double decayFactor(long dtMs) {
        double tau = p.getDecayTauSeconds() * 1000.0;
        return tau <= 0 || dtMs <= 0 ? 1.0 : Math.exp(-dtMs / tau);
    }

    private void decay(ClientProfile c, long now) {
        double f = decayFactor(now - c.lastDecay);
        c.failures *= f;
        c.suspicious *= f;
        c.failedLogins *= f;
        c.burst *= f;
        c.lastDecay = now;
    }

    private void slide(ClientProfile c, long now) {
        long w = p.getWindowSeconds() * 1000L;
        while (!c.window.isEmpty() && now - c.window.peekFirst() > w) c.window.removeFirst();
    }

    String matchSuspicious(String pathAndQuery) {
        if (pathAndQuery == null) return null;
        String x = pathAndQuery.toLowerCase(Locale.ROOT);
        for (String pattern : p.getSuspiciousPatterns()) {
            if (x.contains(pattern.toLowerCase(Locale.ROOT))) return pattern;
        }
        return null;
    }

    private static long secondsUntil(long until, long now) {
        return Math.max(1, (until - now + 999) / 1000);
    }

    /** True if the path should bypass threat scoring entirely. */
    public boolean isExcluded(String path) {
        for (String e : p.getExcludedPaths()) {
            if (e.equals("/")) { if (path.equals("/")) return true; }
            else if (path.equals(e) || path.startsWith(e.endsWith("/") ? e : e + "/") || path.equals(e)) return true;
        }
        return false;
    }
}
