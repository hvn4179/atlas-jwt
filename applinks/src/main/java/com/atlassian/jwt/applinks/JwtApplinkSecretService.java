package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;

public interface JwtApplinkSecretService
{

    void issueSharedSecrets(ApplicationLink applicationLink);

    void revokeSharedSecrets(ApplicationLink applicationLink);

}
