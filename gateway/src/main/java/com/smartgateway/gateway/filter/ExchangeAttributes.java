package com.smartgateway.gateway.filter;

/** Keys used to pass threat information between the web filter and the gateway filter. */
public final class ExchangeAttributes {
    public static final String CLIENT_IP = "smartgateway.clientIp";
    public static final String USER_KEY = "smartgateway.userKey";
    public static final String USER_DECISION = "smartgateway.userDecision";

    private ExchangeAttributes() { }
}
