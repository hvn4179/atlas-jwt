package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.JwtConfiguration;
import com.atlassian.jwt.core.SystemPropertyJwtConfiguration;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.reader.UnverifiedJwtReader;

public class NimbusJwtReaderFactory implements JwtReaderFactory
{
    private final JwtConfiguration jwtConfiguration;

    public NimbusJwtReaderFactory()
    {
        this(new SystemPropertyJwtConfiguration());
    }

    public NimbusJwtReaderFactory(JwtConfiguration jwtConfiguration)
    {
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    public JwtReader macVerifyingReader(String sharedSecret)
    {
        return new NimbusMacJwtReader(sharedSecret, jwtConfiguration);
    }

    @Override
    public UnverifiedJwtReader unverified()
    {
        return new NimbusUnverifiedJwtReader();
    }


}
