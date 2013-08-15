package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtSigningException;
import com.atlassian.jwt.exception.JwtVerificationException;

public interface JwtService
{
    boolean isJwtPeer(ApplicationLink applicationLink);

    ApplinkJwt verifyJwt(String jwt) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException;

    String issueJwt(String jsonPayload, ApplicationLink applicationLink) throws NotAJwtPeerException, JwtSigningException;
}
