package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import javax.annotation.Nonnull;
import java.security.interfaces.RSAPrivateKey;

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

//    public JwtWriter rsSigningWriter(@Nonnull SigningAlgorithm algorithm, @Nonnull RSAPrivateKey privateKey)
//    {
//        return new NimbusJwtWriter(algorithm, new RSASSASigner(privateKey));
//    }
}
