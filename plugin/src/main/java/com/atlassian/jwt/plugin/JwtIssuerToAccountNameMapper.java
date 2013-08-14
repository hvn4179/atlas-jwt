package com.atlassian.jwt.plugin;

public interface JwtIssuerToAccountNameMapper
{
    public String get(String issuer);
}
