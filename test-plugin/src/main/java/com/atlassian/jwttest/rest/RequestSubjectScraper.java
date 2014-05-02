package com.atlassian.jwttest.rest;

import javax.servlet.*;
import java.io.IOException;

import static com.atlassian.jwt.JwtConstants.HttpRequests.JWT_SUBJECT_ATTRIBUTE_NAME;

public class RequestSubjectScraper implements Filter
{
    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        RequestSubjectStore.setSubject((String) request.getAttribute(JWT_SUBJECT_ATTRIBUTE_NAME));
    }

    @Override
    public void destroy()
    {
    }
}
