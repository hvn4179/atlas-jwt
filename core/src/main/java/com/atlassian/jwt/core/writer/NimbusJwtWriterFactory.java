package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;
import com.nimbusds.jose.crypto.MACSigner;

import javax.annotation.Nonnull;

/**
 * Factory for {@link JwtWriter} implementations that use the "Nimbus JOSE+JWT" library.
 */
public class NimbusJwtWriterFactory implements JwtWriterFactory
{
    @Nonnull
    @Override
    public JwtWriter macSigningWriter(@Nonnull SigningAlgorithm algorithm, @Nonnull String sharedSecret)
    {
        return new NimbusJwtWriter(algorithm, new MACSigner(sharedSecret));
    }
}
