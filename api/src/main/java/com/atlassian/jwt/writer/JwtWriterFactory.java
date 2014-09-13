package com.atlassian.jwt.writer;

import com.atlassian.jwt.SigningAlgorithm;

import javax.annotation.Nonnull;
import java.security.interfaces.RSAPrivateKey;

/**
 * Factory for {@link JwtJsonBuilderFactory}.
 *
 * @since 1.0
 */
public interface JwtWriterFactory
{
    @Nonnull
    JwtWriter macSigningWriter(@Nonnull SigningAlgorithm algorithm, @Nonnull String sharedSecret);

//    @Nonnull
//    JwtWriter rsSigningWriter(@Nonnull SigningAlgorithm algorithm, @Nonnull RSAPrivateKey privateKey);
}
