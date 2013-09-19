package com.atlassian.jwt;

import java.util.Map;

/**
 * HTTP request that can be signed for use as a JWT claim.
 *
 * @since 1.0
 */
public interface CanonicalHttpRequest
{
    public String getMethod();
    public String getUri();
    public String getContextPath();
    public Map<String, String[]> getParameterMap();
}
