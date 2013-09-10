package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.JwtConfiguration;
import com.atlassian.jwt.core.SystemClock;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACVerifier;

public class NimbusMacJwtReader extends NimbusJwtReader
{
    public NimbusMacJwtReader(String sharedSecret, JWSAlgorithm algorithm, JwtConfiguration jwtConfiguration)
    {
        this(sharedSecret, algorithm, jwtConfiguration, SystemClock.getInstance());
    }

    public NimbusMacJwtReader(String sharedSecret, JWSAlgorithm algorithm, JwtConfiguration jwtConfiguration, Clock clock)
    {
        super(new MACVerifier(sharedSecret), algorithm, jwtConfiguration, clock);
    }
}
