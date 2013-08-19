package com.atlassian.jwt.core;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.VerifiedJwt;

/**
 *
 */
public class SimpleJwt implements VerifiedJwt, UnverifiedJwt
{
    private final String iss;
    private final String prn;
    private final String payload;

    public SimpleJwt(String iss, String prn, String payload)
    {
        this.iss = iss;
        this.prn = prn;
        this.payload = payload;
    }

    @Override
    public String getIssuer()
    {
        return iss;
    }

    @Override
    public String getPrincipal()
    {
        return prn;
    }

    @Override
    public String getJsonPayload()
    {
        return payload;
    }
}
