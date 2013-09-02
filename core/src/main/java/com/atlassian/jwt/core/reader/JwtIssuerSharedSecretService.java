package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;

public interface JwtIssuerSharedSecretService
{
    public String getSharedSecret(String issuer) throws JwtIssuerLacksSharedSecretException;
}
