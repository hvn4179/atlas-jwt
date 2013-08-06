package com.atlassian.auth.jwt.serviceprovider;

import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletRequest;

/**
 * Author: pbrownlow
 * Date: 6/08/13
 * Time: 5:20 PM
 */
public class JwtUtils
{
    public static final String JWT_PARAM_NAME = "jwt";
    public static final String JWT_REQUEST_FLAG = "com.atlassian.oath.jwt-request-flag";

    public static boolean requestContainsJwt(ServletRequest request)
    {
        return !StringUtils.isEmpty(request.getParameter(JwtUtils.JWT_PARAM_NAME));
    }
}
