package com.smartgateway.gateway.audit;

public record BlacklistEntry(String clientKey, long blockedUntil, int offences, String reason) { }
