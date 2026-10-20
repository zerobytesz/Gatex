package com.smartgateway.gateway.auth;

public record UserAccount(String username, String passwordHash, String role) { }
