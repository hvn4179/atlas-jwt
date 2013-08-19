package com.atlassian.jwt.writer;

import com.atlassian.jwt.SigningAlgorithm;

public interface JwtWriterFactory
{
    JwtWriter macSigningWriter(SigningAlgorithm algorithm, String secret);
}
