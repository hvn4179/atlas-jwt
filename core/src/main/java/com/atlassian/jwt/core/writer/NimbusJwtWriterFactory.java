package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;
import com.nimbusds.jose.crypto.MACSigner;

/**
 *
 */
public class NimbusJwtWriterFactory implements JwtWriterFactory
{
    @Override
    public JwtWriter macSigningWriter(SigningAlgorithm algorithm, String sharedSecret)
    {
        return new NimbusJwtWriter(algorithm, new MACSigner(sharedSecret));
    }
}
