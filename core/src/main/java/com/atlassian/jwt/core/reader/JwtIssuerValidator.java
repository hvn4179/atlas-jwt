package com.atlassian.jwt.core.reader;

public interface JwtIssuerValidator
{
    public boolean isValid(String issuer);
}
