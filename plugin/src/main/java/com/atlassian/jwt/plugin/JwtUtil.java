package com.atlassian.jwt.plugin;

import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletRequest;

public class JwtUtil
{
    public static final String JWT_PARAM_NAME = "jwt";
    public static final String JWT_REQUEST_FLAG = "com.atlassian.jwt.is-jwt-request";

    public static boolean requestContainsJwt(ServletRequest request)
    {
        return !StringUtils.isEmpty(request.getParameter(JwtUtil.JWT_PARAM_NAME));
    }
}
