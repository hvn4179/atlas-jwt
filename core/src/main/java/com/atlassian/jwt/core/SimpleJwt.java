package com.atlassian.jwt.core;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.VerifiedJwt;

/**
 *
 */
public class SimpleJwt implements VerifiedJwt, UnverifiedJwt
{
    private final String iss;
    private final String sub;
    private final String payload;

    public SimpleJwt(String iss, String sub, String payload)
    {
        this.iss = iss;
        this.sub = sub;
        this.payload = payload;
    }

    @Override
    public String getIssuer()
    {
        return iss;
    }

    @Override
    public String getSubject()
    {
        return sub;
    }

    @Override
    public String getJsonPayload()
    {
        return payload;
    }
}
