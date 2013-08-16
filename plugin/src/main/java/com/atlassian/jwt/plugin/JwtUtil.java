package com.atlassian.jwt.plugin;

import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

public class JwtUtil
{
    public static final String JWT_PARAM_NAME = "jwt";
    public static final String JWT_REQUEST_FLAG = "com.atlassian.jwt.is-jwt-request";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static boolean requestContainsJwt(HttpServletRequest request)
    {
        return extractJwt(request) != null;
    }

    public static String extractJwt(HttpServletRequest request)
    {
        String jwt = getJwtParameter(request);
        if (jwt == null) {
            jwt = getJwtHeaderValue(request);
        }
        return jwt;
    }

    private static String getJwtParameter(HttpServletRequest request)
    {
        String jwtParam = request.getParameter(JwtUtil.JWT_PARAM_NAME);
        return StringUtils.isEmpty(jwtParam) ? null : jwtParam;
    }

    private static String getJwtHeaderValue(HttpServletRequest request)
    {
        Enumeration<String> headers = request.getHeaders(AUTHORIZATION_HEADER);
        while (headers.hasMoreElements())
        {
            String authzHeader = headers.nextElement().trim();
            String first4Chars = authzHeader.substring(0, Math.min(4, authzHeader.length()));
            if ("JWT ".equalsIgnoreCase(first4Chars))
            {
                return authzHeader.substring(4);
            }
        }
        return null;
    }
}
