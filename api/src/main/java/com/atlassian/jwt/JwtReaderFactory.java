package com.atlassian.jwt;

public interface JwtReaderFactory
{
    JwtReader forSharedSecret(JwsAlgorithm algorithm, String secret);
}
