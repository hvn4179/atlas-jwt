package com.atlassian.jwt.core;

import com.atlassian.jwt.JwtConstants;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Enumeration;

public class JwtUtil
{
    public static final String JWT_REQUEST_FLAG = "com.atlassian.jwt.is-jwt-request";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * The encoding used to represent characters as bytes.
     */
    private static final String ENCODING = "UTF-8";
    /**
     * As appears between "value1" and "param2" in the URL "http://server/path?param1=value1&param2=value2".
     */
    public static final char QUERY_PARAMS_SEPARATOR = '&';

    public static boolean requestContainsJwt(HttpServletRequest request)
    {
        return extractJwt(request) != null;
    }

    public static String extractJwt(HttpServletRequest request)
    {
        String jwt = getJwtParameter(request);
        if (jwt == null)
        {
            jwt = getJwtHeaderValue(request);
        }
        return jwt;
    }

    private static String getJwtParameter(HttpServletRequest request)
    {
        String jwtParam = request.getParameter(JwtConstants.JWT_PARAM_NAME);
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

    /**
     * {@link URLEncoder}#encode() but encode some characters differently to URLEncoder, to match OAuth1 and VisualVault.
     * @param str {@link String} to be percent-encoded
     * @return encoded {@link String}
     * @throws {@link UnsupportedEncodingException} if {@link URLEncoder} does not support {@link JwtUtil}#ENCODING
     */
    public static String percentEncode(String str) throws UnsupportedEncodingException
    {
        if (str == null)
        {
            return "";
        }

        return URLEncoder.encode(str, ENCODING)
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
    }
}
