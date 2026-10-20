package com.smartgateway.gateway.threat;

/** Notified whenever the engine blacklists a client key (used to persist the blacklist). */
@FunctionalInterface
public interface BlockListener {
    void onBlocked(String key, long blockedUntilEpochMs, int offences, String reason);
}
