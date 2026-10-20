package com.smartgateway.gateway.audit;

/** One audited request: who, what, the HTTP outcome and the threat decision applied. */
public record SecurityEvent(long timestamp, String clientKey, String ip, String method, String path,
                            int status, int risk, String level, String action) { }
