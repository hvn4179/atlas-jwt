package com.atlassian.jwt.reader;

import com.atlassian.jwt.JwsAlgorithm;

public interface JwtReaderFactory
{
    JwtReader forSharedSecret(JwsAlgorithm algorithm, String secret);

    UnverifiedJwtReader unverified();
}
