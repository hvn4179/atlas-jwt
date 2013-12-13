package com.atlassian.jwt.core.http;

import org.apache.commons.lang.StringUtils;

import static com.atlassian.jwt.JwtConstants.JWT_PARAM_NAME;
import static com.atlassian.jwt.core.http.JwtHttpConstants.AUTHORIZATION_HEADER;
import static com.atlassian.jwt.core.http.JwtHttpConstants.JWT_AUTH_HEADER_PREFIX;

public class JwtDefaultRequestHelper implements JwtRequestHelper
{
    private final HttpRequestWrapper requestWrapper;

    public JwtDefaultRequestHelper(HttpRequestWrapper requestWrapper)
    {
        this.requestWrapper = requestWrapper;
    }

    @Override
    public String extractJwt()
    {
        String jwt = getJwtParameter();
        if (jwt == null)
        {
            jwt = getJwtHeaderValue();
        }
        return jwt;
    }

    private String getJwtParameter()
    {
        String jwtParam = requestWrapper.getParameter(JWT_PARAM_NAME);
        return StringUtils.isEmpty(jwtParam) ? null : jwtParam;
    }

    private String getJwtHeaderValue()
    {
        Iterable<String> headers = requestWrapper.getHeaderValues(AUTHORIZATION_HEADER);
        for (String header : headers)
        {
            String authzHeader = header.trim();
            String first4Chars = authzHeader.substring(0, Math.min(4, authzHeader.length()));
            if (JWT_AUTH_HEADER_PREFIX.equalsIgnoreCase(first4Chars))
            {
                return authzHeader.substring(4);
            }
        }

        return null;
    }
}
