package com.atlassian.jwt.core.http.auth;

public interface JwtAuthenticator<REQ, RES, S>
{
    S authenticate(REQ request, RES response);
}
