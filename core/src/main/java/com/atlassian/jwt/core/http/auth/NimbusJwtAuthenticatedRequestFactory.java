package com.atlassian.jwt.core.http.auth;

import org.apache.http.client.methods.HttpRequestBase;

public class NimbusJwtAuthenticatedRequestFactory implements JwtAuthenticatedRequestFactory
{
    public NimbusJwtAuthenticatedRequestFactory()
    {
        super();
    }

    @Override
    public HttpRequestBase createJwtRs256AuthenticatedRequest(HttpRequestBase requestBase, String issuer, String subject)
    {
        return null;
    }
}
