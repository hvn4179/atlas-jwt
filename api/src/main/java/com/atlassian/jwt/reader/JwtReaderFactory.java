package com.atlassian.jwt.reader;

import com.atlassian.jwt.SigningAlgorithm;

public interface JwtReaderFactory
{
    JwtReader forSharedSecret(SigningAlgorithm algorithm, String secret);

    UnverifiedJwtReader unverified();
}
