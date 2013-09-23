package com.atlassian.jwt;

import java.util.Map;

/**
 * HTTP request that can be signed for use as a JWT claim.
 *
 * @since 1.0
 */
public interface CanonicalHttpRequest
{
    /**
     * HTTP method (e.g. "GET", "POST" etc).
     * @return the HTTP method in upper-case.
     */
    public String getMethod();

    /**
     * The part of an absolute URL that is after the protocol, server, port and context path.
     * E.g. "/the_uri" in "http://server:80/context/the_uri?param=value".
     * @return the relative URI with no case manipulation.
     */
    public String getRelativeUri();

    /**
     * The part of an absolute URL that has been added by a reverse proxy, or "/" if no such redirection has occurred.
     * E.g. "/context" after "http://subdomain.server:80/the_uri?param=value" was redirected to "http://server:80/context/the_uri?param=value".
     * @return the context path with no case manipulation.
     */
    public String getContextPath();

    /**
     * The {@link Map} of parameter-name to parameter-values.
     * @return {@link Map} representing { parameter-name-1 to { parameter-value-1, parameter-value-2 ... }, parameter-name-2 to { ... }, ... }
     */
    public Map<String, String[]> getParameterMap();
}
