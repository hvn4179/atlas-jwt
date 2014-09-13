package com.atlassian.jwt.core.http.auth;


import org.apache.http.client.methods.HttpRequestBase;

public interface JwtAuthenticatedRequestFactory
{
    HttpRequestBase createJwtRs256AuthenticatedRequest(HttpRequestBase requestBase, String issuer, String subject);
}
