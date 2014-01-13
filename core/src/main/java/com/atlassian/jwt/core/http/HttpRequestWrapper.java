package com.atlassian.jwt.core.http;

import javax.annotation.Nullable;

import com.atlassian.jwt.CanonicalHttpRequest;

/**
 * A small abstraction over Http requests that allows reuse in non javax.servlet frameworks like Play
 */
public interface HttpRequestWrapper
{
    @Nullable
    String getParameter(String parameterName);

    Iterable<String> getHeaderValues(String headerName);

    CanonicalHttpRequest getCanonicalHttpRequest();
}
