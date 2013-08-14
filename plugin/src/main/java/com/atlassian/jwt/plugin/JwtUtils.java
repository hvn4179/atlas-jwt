package com.atlassian.jwt.plugin;

import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletRequest;

public class JwtUtils
{
    public static final String JWT_PARAM_NAME = "jwt";
    public static final String JWT_REQUEST_FLAG = "com.atlassian.oath.jwt-request-flag";

    public static boolean requestContainsJwt(ServletRequest request)
    {
        return !StringUtils.isEmpty(request.getParameter(JwtUtils.JWT_PARAM_NAME));
    }
}
