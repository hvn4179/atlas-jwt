package com.atlassian.jwttest.rest;

import javax.servlet.*;
import java.io.IOException;

/**
 * So that the {@link RequestSubjectScraper} and {@link WhoAmIResource} Filters get and set a clean subject every time.
 */
public class RequestSubjectResetter implements Filter
{
    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        RequestSubjectStore.setSubject(null);
    }

    @Override
    public void destroy()
    {
    }
}
