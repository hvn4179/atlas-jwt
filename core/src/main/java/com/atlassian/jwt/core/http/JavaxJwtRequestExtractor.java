package com.atlassian.jwt.core.http;

import javax.servlet.http.HttpServletRequest;

import com.atlassian.jwt.CanonicalHttpRequest;

public class JavaxJwtRequestExtractor extends AbstractJwtRequestExtractor<HttpServletRequest>
{
    protected JavaxHttpRequestWrapper wrapRequest(HttpServletRequest request)
    {
        return new JavaxHttpRequestWrapper(request);
    }
}
