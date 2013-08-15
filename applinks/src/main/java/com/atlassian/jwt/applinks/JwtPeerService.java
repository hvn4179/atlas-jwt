package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;

public interface JwtPeerService
{
    void issueSharedSecret(ApplicationLink applicationLink, String path) throws JwtRegistrationFailed;

    void revokeSharedSecret(ApplicationLink applicationLink);
}
