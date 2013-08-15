package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.reader.UnverifiedJwtReader;

public class NimbusJwtReaderFactory implements JwtReaderFactory
{

    @Override
    public JwtReader forSharedSecret(SigningAlgorithm algorithm, String secret)
    {
        switch (algorithm)
        {
            case HS256:
                return new NimbusMacJwtReader(algorithm, secret);
            default:
                throw new IllegalArgumentException("Unrecognised JWS algorithm: " + algorithm);
        }
    }

    @Override
    public UnverifiedJwtReader unverified()
    {
        return new NimbusUnverifiedJwtReader();
    }

}
