package com.atlassian.jwttest.rest;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
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
        chain.doFilter(request, response);
    }

    @Override
    public void destroy()
    {
    }
}
