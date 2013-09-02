package com.atlassian.jwt.server.servlet;

import com.atlassian.jwt.core.reader.JwtIssuerSharedSecretService;
import com.atlassian.jwt.core.reader.JwtIssuerValidator;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.server.SecretStore;

public class TrivialJwtPeerSharedSecretService implements JwtIssuerValidator, JwtIssuerSharedSecretService
{
    private final SecretStore secretStore;

    public TrivialJwtPeerSharedSecretService(SecretStore secretStore)
    {
        this.secretStore = secretStore;
    }

    @Override
    public boolean isValid(String issuer)
    {
        return secretStore.getClientId().equals(issuer);
    }

    @Override
    public String getSharedSecret(String issuer) throws JwtIssuerLacksSharedSecretException
    {
        if (!isValid(issuer))
        {
            throw new IllegalArgumentException(String.format("Issuer unknown: '%s'", issuer));
        }

        String secret = secretStore.getSecret();

        if (null == secret)
        {
            throw new JwtIssuerLacksSharedSecretException(issuer);
        }

        return secret;
    }
}
