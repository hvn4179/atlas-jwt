package com.atlassian.jwt.core.http;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import com.google.common.base.Optional;

class HttpServletRequestRequestWrapper implements HttpRequestWrapper
{
    private final HttpServletRequest request;

    public HttpServletRequestRequestWrapper(HttpServletRequest request)
    {
        this.request = request;
    }

    @Override
    public Optional<String> getParameter(String parameterName)
    {
        return Optional.fromNullable(request.getParameter(parameterName));
    }

    @Override
    @SuppressWarnings(value = "unchecked")
    public Iterable<String> getHeaderValues(String headerName)
    {
        return Collections.list(request.getHeaders(headerName));
    }
}
