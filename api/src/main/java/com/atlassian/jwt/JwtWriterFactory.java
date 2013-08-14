package com.atlassian.jwt;

public interface JwtWriterFactory
{
    JwtWriter forSharedSecret(JwsAlgorithm algorithm, String secret);
}
