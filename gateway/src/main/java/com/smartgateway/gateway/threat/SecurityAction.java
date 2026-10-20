package com.smartgateway.gateway.threat;

/**
 * Action applied by the gateway, ordered from least to most severe.
 * THROTTLE / STRONG_THROTTLE: request is forwarded after a delay and under a tighter token bucket.
 * RATE_LIMITED: the client's adaptive token bucket is empty, request rejected with 429.
 * BLOCK: the client is temporarily blacklisted, request rejected with 429.
 */
public enum SecurityAction {
    ALLOW, THROTTLE, STRONG_THROTTLE, RATE_LIMITED, BLOCK;

    public boolean denies() { return this == RATE_LIMITED || this == BLOCK; }
}
