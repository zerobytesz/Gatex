package com.smartgateway.gateway.threat;

import java.util.ArrayDeque;
import java.util.Deque;

/** Mutable behaviour state for one client key. All access is synchronized on the instance by ThreatEngine. */
final class ClientProfile {
    final String key;
    final Scope scope;
    final Deque<Long> window = new ArrayDeque<>();
    double failures;
    double suspicious;
    double failedLogins;
    double burst;
    long lastDecay;
    long lastSeen;
    long blockedUntil;
    int offences;
    double tokens = -1;      // -1 = bucket not yet initialised
    long lastRefill;
    int lastRisk;
    ThreatLevel level = ThreatLevel.LOW;
    String lastReason = "";

    ClientProfile(String key, Scope scope, long now) {
        this.key = key;
        this.scope = scope;
        this.lastDecay = now;
        this.lastSeen = now;
        this.lastRefill = now;
    }
}
