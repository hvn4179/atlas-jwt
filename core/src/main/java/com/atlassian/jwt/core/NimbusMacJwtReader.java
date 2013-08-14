package com.atlassian.jwt.core;

import com.nimbusds.jose.crypto.MACVerifier;

public class NimbusMacJwtReader extends NimbusJwtReader
{
    public NimbusMacJwtReader(String sharedSecret, Clock clock)
    {
        super(new MACVerifier(sharedSecret), clock);
    }

    public NimbusMacJwtReader(String sharedSecret)
    {
        this(sharedSecret, SystemClock.getInstance());
    }
}
