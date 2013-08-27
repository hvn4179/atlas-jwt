package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.applinks.ApplinkJwt;

/**
 *
 */
public class SimpleApplinkJwt implements ApplinkJwt
{
    private final VerifiedJwt jwt;
    private final ApplicationLink peer;

    public SimpleApplinkJwt(VerifiedJwt jwt, ApplicationLink peer)
    {
        this.jwt = jwt;
        this.peer = peer;
    }

    @Override
    public VerifiedJwt getJwt()
    {
        return jwt;
    }

    @Override
    public ApplicationLink getPeer()
    {
        return peer;
    }
}
