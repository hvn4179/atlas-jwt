package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class CanonicalHttpServletRequest implements CanonicalHttpRequest
{
    private final HttpServletRequest request;

    public CanonicalHttpServletRequest(final HttpServletRequest request)
    {
        this.request = request;
    }

    @Override
    public String getMethod()
    {
        return request.getMethod();
    }

    @Override
    public String getRelativeUri()
    {
        return request.getRequestURI();
    }

    @Override
    public String getContextPath()
    {
        return request.getContextPath();
    }

    @Override
    public Map<String, String[]> getParameterMap()
    {
        return request.getParameterMap();
    }
}
