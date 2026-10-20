package com.smartgateway.gateway.threat;

/**
 * Outcome of evaluating one request for one client key.
 *
 * @param action            mitigation to apply
 * @param level             threat level after this request
 * @param risk              bounded risk score 0..100
 * @param requestsInWindow  requests observed in the current sliding window
 * @param retryAfterSeconds suggested Retry-After for denied requests (0 otherwise)
 * @param newlyBlocked      true only on the request that triggered a new block
 */
public record Decision(SecurityAction action, ThreatLevel level, int risk, int requestsInWindow,
                       long retryAfterSeconds, boolean newlyBlocked) {

    public static final Decision NONE = new Decision(SecurityAction.ALLOW, ThreatLevel.LOW, 0, 0, 0, false);

    public boolean denied() { return action.denies(); }

    /** Returns the more severe of two decisions (used to combine IP-scope and user-scope results). */
    public static Decision mostSevere(Decision a, Decision b) {
        if (a == null) return b;
        if (b == null) return a;
        if (a.action.ordinal() != b.action.ordinal()) return a.action.ordinal() > b.action.ordinal() ? a : b;
        return a.risk >= b.risk ? a : b;
    }
}
