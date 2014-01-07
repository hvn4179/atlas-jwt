package com.atlassian.jwttest.rest;

import javax.servlet.*;
import java.io.IOException;

import static com.atlassian.jwt.JwtConstants.HttpRequests.ADD_ON_ID_ATTRIBUTE_NAME;

/**
 * Removes the request attribute that identifies the add-on so that the ApiScopingFilter does not do authorisation checks.
 * We aren't interested in testing authorisation here, only authentication.
 * Because scopes are implemented as a whitelist our "whoami" test resource is naturally not in any list of resources that atlassian-connect knows,
 * resulting in the ApiScopingFilter always rejecting any attempt to access it.
 */
public class ApiScopingFilterDisabler implements Filter
{
    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        // do nothing
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        request.removeAttribute(ADD_ON_ID_ATTRIBUTE_NAME);
        chain.doFilter(request, response);
    }

    @Override
    public void destroy()
    {
        // do nothing
    }
}
