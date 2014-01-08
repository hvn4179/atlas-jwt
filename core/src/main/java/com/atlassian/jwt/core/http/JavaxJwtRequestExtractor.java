package com.atlassian.jwt.core.http;

import javax.servlet.http.HttpServletRequest;

import com.atlassian.jwt.CanonicalHttpRequest;

/**
 * An implementation of JwtRequestExtractor for javax.servlet.http.HttpServletRequest
 */
public class JavaxJwtRequestExtractor extends AbstractJwtRequestExtractor<HttpServletRequest>
{
    protected JavaxHttpRequestWrapper wrapRequest(HttpServletRequest request)
    {
        return new JavaxHttpRequestWrapper(request);
    }
}
