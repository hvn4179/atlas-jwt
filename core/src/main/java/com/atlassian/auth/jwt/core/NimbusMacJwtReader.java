package com.atlassian.auth.jwt.core;

import com.nimbusds.jose.crypto.MACVerifier;

/**
 * Author: pbrownlow
 * Date: 6/08/13
 * Time: 1:56 PM
 */
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
