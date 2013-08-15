package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.SystemClock;
import com.nimbusds.jose.crypto.MACVerifier;

public class NimbusMacJwtReader extends NimbusJwtReader
{
    public NimbusMacJwtReader(SigningAlgorithm algorithm, String sharedSecret, Clock clock)
    {
        super(algorithm, new MACVerifier(sharedSecret), clock);
    }

    public NimbusMacJwtReader(SigningAlgorithm algorithm, String sharedSecret)
    {
        this(algorithm, sharedSecret, SystemClock.getInstance());
    }
}
