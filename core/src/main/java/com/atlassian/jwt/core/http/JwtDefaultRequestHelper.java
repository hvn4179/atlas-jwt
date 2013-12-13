package com.atlassian.jwt.core.http;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import com.atlassian.jwt.JwtConstants;
import com.google.common.base.Optional;
import org.apache.commons.lang.StringUtils;

public class JwtDefaultRequestHelper implements JwtRequestHelper
{
    private final HttpRequestWrapper requestWrapper;

    public JwtDefaultRequestHelper(HttpRequestWrapper requestWrapper) {

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
        String jwtParam = requestWrapper.getParameter(JwtConstants.JWT_PARAM_NAME).orNull();
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
