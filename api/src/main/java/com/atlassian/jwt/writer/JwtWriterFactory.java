package com.atlassian.jwt.writer;

import com.atlassian.jwt.SigningAlgorithm;

public interface JwtWriterFactory
{
    JwtWriter forSharedSecret(SigningAlgorithm algorithm, String secret);
}
