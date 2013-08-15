package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.jwt.VerifiedJwt;

public interface ApplinkJwt
{
    VerifiedJwt getJwt();

    ApplicationLink getPeer();
}
