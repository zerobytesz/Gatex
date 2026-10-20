package com.smartgateway.gateway.threat;

import java.util.ArrayList;
import java.util.List;

/**
 * Tunable parameters of the adaptive threat engine.
 * Bound from {@code smartgateway.threat.*} in application.yml (see ThreatConfig).
 * This class deliberately has no Spring dependency so the engine can be unit-tested in isolation.
 */
public class ThreatProperties {

    // ---- behaviour observation window ----
    private int windowSeconds = 10;
    /** Requests per window considered normal for one authenticated user. */
    private int normalLimit = 50;
    /** IP-scope limits are this many times the user-scope limits (several users may share one IP/NAT). */
    private int ipLimitMultiplier = 5;

    // ---- risk model weights and caps (risk is bounded to 0..100) ----
    private double rateWeight = 2;
    private double rateCap = 60;
    private double burstCap = 30;
    private double failureWeight = 5;
    private double failureCap = 25;
    private double suspiciousWeight = 15;
    private double suspiciousCap = 60;
    private double failedLoginWeight = 12;
    private double failedLoginCap = 80;
    /** Accumulated evidence decays exponentially with this time constant (seconds). */
    private double decayTauSeconds = 60;

    // ---- threat level thresholds ----
    private int mediumThreshold = 30;
    private int highThreshold = 60;
    private int criticalThreshold = 80;

    // ---- mitigation ----
    private int blockSeconds = 60;
    /** Block duration doubles for each repeat offence, up to 2^maxBlockEscalation times the base. */
    private int maxBlockEscalation = 4;
    private double bucketCapacityLow = 40;
    private double bucketRefillLow = 10;
    private double bucketCapacityMedium = 20;
    private double bucketRefillMedium = 4;
    private double bucketCapacityHigh = 8;
    private double bucketRefillHigh = 1;
    private long throttleDelayMediumMs = 100;
    private long throttleDelayHighMs = 300;

    // ---- global traffic health ----
    /** Total requests per window the gateway is sized for; above this, all rate limits shrink proportionally. */
    private long globalCapacityPerWindow = 5000;
    private double minHealthFactor = 0.25;

    // ---- housekeeping ----
    private long idleEvictSeconds = 1800;
    private int maxProfiles = 100_000;

    private String loginPath = "/auth/login";
    private List<String> suspiciousPatterns = new ArrayList<>(List.of(
            "/admin", "..", "%2e%2e", "/etc/passwd", "union select", "union%20select", "union+select",
            "' or ", "%27%20or", "%27+or", "or 1=1", "or%201=1", "<script", "%3cscript", "sleep(", "drop table", "drop%20table"));
    /** Paths not scored at all (monitoring, dashboard assets, admin API used by the dashboard). Prefix match; "/" is exact. */
    private List<String> excludedPaths = new ArrayList<>(List.of(
            "/", "/index.html", "/dashboard.html", "/favicon.ico", "/actuator", "/api/admin"));

    public double bucketCapacity(ThreatLevel level) {
        return switch (level) { case LOW -> bucketCapacityLow; case MEDIUM -> bucketCapacityMedium; case HIGH -> bucketCapacityHigh; case CRITICAL -> 0; };
    }
    public double bucketRefillPerSecond(ThreatLevel level) {
        return switch (level) { case LOW -> bucketRefillLow; case MEDIUM -> bucketRefillMedium; case HIGH -> bucketRefillHigh; case CRITICAL -> 0; };
    }
    public long throttleDelayMs(SecurityAction action) {
        return switch (action) { case THROTTLE -> throttleDelayMediumMs; case STRONG_THROTTLE -> throttleDelayHighMs; default -> 0; };
    }

    // ---- getters / setters (required for Spring property binding) ----
    public int getWindowSeconds() { return windowSeconds; }
    public void setWindowSeconds(int v) { windowSeconds = v; }
    public int getNormalLimit() { return normalLimit; }
    public void setNormalLimit(int v) { normalLimit = v; }
    public int getIpLimitMultiplier() { return ipLimitMultiplier; }
    public void setIpLimitMultiplier(int v) { ipLimitMultiplier = v; }
    public double getRateWeight() { return rateWeight; }
    public void setRateWeight(double v) { rateWeight = v; }
    public double getRateCap() { return rateCap; }
    public void setRateCap(double v) { rateCap = v; }
    public double getBurstCap() { return burstCap; }
    public void setBurstCap(double v) { burstCap = v; }
    public double getFailureWeight() { return failureWeight; }
    public void setFailureWeight(double v) { failureWeight = v; }
    public double getFailureCap() { return failureCap; }
    public void setFailureCap(double v) { failureCap = v; }
    public double getSuspiciousWeight() { return suspiciousWeight; }
    public void setSuspiciousWeight(double v) { suspiciousWeight = v; }
    public double getSuspiciousCap() { return suspiciousCap; }
    public void setSuspiciousCap(double v) { suspiciousCap = v; }
    public double getFailedLoginWeight() { return failedLoginWeight; }
    public void setFailedLoginWeight(double v) { failedLoginWeight = v; }
    public double getFailedLoginCap() { return failedLoginCap; }
    public void setFailedLoginCap(double v) { failedLoginCap = v; }
    public double getDecayTauSeconds() { return decayTauSeconds; }
    public void setDecayTauSeconds(double v) { decayTauSeconds = v; }
    public int getMediumThreshold() { return mediumThreshold; }
    public void setMediumThreshold(int v) { mediumThreshold = v; }
    public int getHighThreshold() { return highThreshold; }
    public void setHighThreshold(int v) { highThreshold = v; }
    public int getCriticalThreshold() { return criticalThreshold; }
    public void setCriticalThreshold(int v) { criticalThreshold = v; }
    public int getBlockSeconds() { return blockSeconds; }
    public void setBlockSeconds(int v) { blockSeconds = v; }
    public int getMaxBlockEscalation() { return maxBlockEscalation; }
    public void setMaxBlockEscalation(int v) { maxBlockEscalation = v; }
    public double getBucketCapacityLow() { return bucketCapacityLow; }
    public void setBucketCapacityLow(double v) { bucketCapacityLow = v; }
    public double getBucketRefillLow() { return bucketRefillLow; }
    public void setBucketRefillLow(double v) { bucketRefillLow = v; }
    public double getBucketCapacityMedium() { return bucketCapacityMedium; }
    public void setBucketCapacityMedium(double v) { bucketCapacityMedium = v; }
    public double getBucketRefillMedium() { return bucketRefillMedium; }
    public void setBucketRefillMedium(double v) { bucketRefillMedium = v; }
    public double getBucketCapacityHigh() { return bucketCapacityHigh; }
    public void setBucketCapacityHigh(double v) { bucketCapacityHigh = v; }
    public double getBucketRefillHigh() { return bucketRefillHigh; }
    public void setBucketRefillHigh(double v) { bucketRefillHigh = v; }
    public long getThrottleDelayMediumMs() { return throttleDelayMediumMs; }
    public void setThrottleDelayMediumMs(long v) { throttleDelayMediumMs = v; }
    public long getThrottleDelayHighMs() { return throttleDelayHighMs; }
    public void setThrottleDelayHighMs(long v) { throttleDelayHighMs = v; }
    public long getGlobalCapacityPerWindow() { return globalCapacityPerWindow; }
    public void setGlobalCapacityPerWindow(long v) { globalCapacityPerWindow = v; }
    public double getMinHealthFactor() { return minHealthFactor; }
    public void setMinHealthFactor(double v) { minHealthFactor = v; }
    public long getIdleEvictSeconds() { return idleEvictSeconds; }
    public void setIdleEvictSeconds(long v) { idleEvictSeconds = v; }
    public int getMaxProfiles() { return maxProfiles; }
    public void setMaxProfiles(int v) { maxProfiles = v; }
    public String getLoginPath() { return loginPath; }
    public void setLoginPath(String v) { loginPath = v; }
    public List<String> getSuspiciousPatterns() { return suspiciousPatterns; }
    public void setSuspiciousPatterns(List<String> v) { suspiciousPatterns = v; }
    public List<String> getExcludedPaths() { return excludedPaths; }
    public void setExcludedPaths(List<String> v) { excludedPaths = v; }
}
