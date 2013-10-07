package com.atlassian.jwt.writer;

import com.atlassian.jwt.SigningAlgorithm;

import javax.annotation.Nonnull;

/**
 * Factory for {@link JwtJsonBuilderFactory}.
 *
 * @since 1.0
 */
public interface JwtWriterFactory
{
    @Nonnull
    JwtWriter macSigningWriter(@Nonnull SigningAlgorithm algorithm, @Nonnull String sharedSecret);
}
