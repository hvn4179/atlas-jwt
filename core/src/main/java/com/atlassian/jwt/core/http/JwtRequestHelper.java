package com.atlassian.jwt.core.http;

public interface JwtRequestHelper
{
    final String JWT_REQUEST_FLAG = "com.atlassian.jwt.is-jwt-request";

    final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * The start of a valid Authorization header specifying a JWT message.<p>
     * Note the space at the end of the prefix; the header's format is:
     *  <pre>{@code
     *      JwtUtil.JWT_AUTH_HEADER_PREFIX + "<insert jwt message here>"
     *  }</pre>
     */
    final String JWT_AUTH_HEADER_PREFIX = "JWT ";

    String extractJwt();
}
