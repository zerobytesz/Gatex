package com.smartgateway.gateway.threat;

/** Read-only view of one client profile, used by the dashboard and admin API. */
public record ProfileView(String key, ThreatLevel level, int risk, int requestsInWindow, boolean blocked,
                          long blockedUntil, int offences, long lastSeen, String lastReason) {}
