package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;

public interface JwtApplinkTokenService
{

    boolean isJwtPeer(ApplicationLink applicationLink);

    String extractJsonPayloadFromJwt(String jwt, ApplicationLink applicationLink);

    String issueJwt(String jsonPayload, ApplicationLink applicationLink);

}
