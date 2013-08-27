package com.atlassian.jwt.writer;

import com.atlassian.jwt.SigningAlgorithm;

/**
 * Factory for {@link JwtJsonBuilderFactory}.
 *
 * @since 1.0
 */
public interface JwtWriterFactory
{
    JwtWriter macSigningWriter(SigningAlgorithm algorithm, String sharedSecret);
}
