package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.JwtConfiguration;

public class NimbusHmac256JwtReader extends NimbusMacJwtReader
{
    public NimbusHmac256JwtReader(String sharedSecret, JwtConfiguration jwtConfiguration)
    {
        super(sharedSecret, jwtConfiguration);
    }

    public NimbusHmac256JwtReader(String sharedSecret, JwtConfiguration jwtConfiguration, Clock clock)
    {
        super(sharedSecret, jwtConfiguration, clock);
    }
}
