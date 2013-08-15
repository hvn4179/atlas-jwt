package com.atlassian.jwt.writer;

import com.atlassian.jwt.JwsAlgorithm;

public interface JwtWriterFactory
{
    JwtWriter forSharedSecret(JwsAlgorithm algorithm, String secret);
}
