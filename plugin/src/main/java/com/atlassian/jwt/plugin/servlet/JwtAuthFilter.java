package com.atlassian.jwt.plugin.servlet;

import com.atlassian.jwt.plugin.JwtUtil;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.AuthenticationListener;
import com.atlassian.sal.api.auth.Authenticator;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthFilter implements Filter
{
    private final Authenticator authenticator;
    private final AuthenticationListener authenticationListener;
    private final AuthenticationController authenticationController;

    public JwtAuthFilter(AuthenticationListener authenticationListener, Authenticator authenticator, AuthenticationController authenticationController)
    {
        this.authenticationListener = authenticationListener;
        this.authenticator = authenticator;
        this.authenticationController = authenticationController;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        if (mayProceed(getHttpServletRequest(request), getHttpServletResponse(response)))
        {
            chain.doFilter(request, response);
        }
    }

    private HttpServletResponse getHttpServletResponse(ServletResponse response)
    {
        return (HttpServletResponse) response;
    }

    private HttpServletRequest getHttpServletRequest(ServletRequest request)
    {
        return (HttpServletRequest) request;
    }

    private boolean mayProceed(HttpServletRequest request, HttpServletResponse response)
    {
        // is it a protected resource? if not, we don't care
        if (!authenticationController.shouldAttemptAuthentication(request))
        {
            authenticationListener.authenticationNotAttempted(request, response);
            return true;
        }

        // if it does NOT involve JWT then we allow the filter chain to continue being processed,
        // TODO: but we want to add the WWW-Authenticate header
        if (!JwtUtil.requestContainsJwt(request))
        {
            authenticationListener.authenticationNotAttempted(request, response);
            return true;
        }

        final Authenticator.Result result = authenticator.authenticate(request, response);

        if (result.getStatus() == Authenticator.Result.Status.FAILED)
        {
            authenticationListener.authenticationFailure(result, request, response);
            return false;
        }

        if (result.getStatus() == Authenticator.Result.Status.ERROR)
        {
            authenticationListener.authenticationError(result, request, response);
            return false;
        }

        authenticationListener.authenticationSuccess(result, request, response);
        markAsJwtRequest(request);

        return true;
    }

    private void markAsJwtRequest(HttpServletRequest request)
    {
        request.setAttribute(JwtUtil.JWT_REQUEST_FLAG, true);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        // do nothing
    }

    @Override
    public void destroy()
    {
        // do nothing
    }
}
