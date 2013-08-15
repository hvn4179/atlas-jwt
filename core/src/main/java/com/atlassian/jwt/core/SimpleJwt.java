package com.atlassian.jwt.core;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.VerifiedJwt;

/**
 *
 */
public class SimpleJwt implements VerifiedJwt, UnverifiedJwt
{
    private final String iss;
    private final String prn;
    private final SigningAlgorithm alg;
    private final String payload;

    public SimpleJwt(String iss, String prn, SigningAlgorithm alg, String payload)
    {
        this.iss = iss;
        this.prn = prn;
        this.alg = alg;
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
        return prn;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public SigningAlgorithm getSigningAlgorithm()
    {
        return alg;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public String getJsonPayload()
    {
        return payload;
    }
}
