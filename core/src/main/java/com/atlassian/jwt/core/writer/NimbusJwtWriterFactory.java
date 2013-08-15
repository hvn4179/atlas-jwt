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
    public JwtWriter forSharedSecret(SigningAlgorithm algorithm, String secret)
    {
        return new NimbusJwtWriter(algorithm, new MACSigner(secret));
    }
}