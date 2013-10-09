package com.atlassian.jwt.plugin.servlet;

import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.plugin.sal.JwtAuthenticator;
import com.atlassian.sal.api.ApplicationProperties;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.AuthenticationListener;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Vector;

import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthFilterTest
{
    private static final String MOCK_JWT = "a.b.c";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    Filter filter;

    @Mock JwtAuthenticator authenticator;
    @Mock AuthenticationListener authenticationListener;
    @Mock AuthenticationController authenticationController;
    @Mock ApplicationProperties applicationProperties;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain chain;

    @Before
    public void setUp()
    {
        filter = new JwtAuthFilter(authenticationListener, authenticator, authenticationController);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://host/service"));
        when(request.getRequestURI()).thenReturn("/service");
        when(request.getMethod()).thenReturn("GET");
        when(request.getContextPath()).thenReturn("");
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(true);
    }

    @Test
    public void authenticationControllerIsNotifiedAndFilterChainContinuesWhenAuthenticationIsSuccessfulAndJwtQueryStringParameterIsValid() throws Exception
    {
        Authenticator.Result.Success success = successResponse();
        setUpSuccessWithJwtQueryStringParameter(success);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationSuccess(eq(success), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verify(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
    }

    @Test
    public void noWwwAuthenticateHeaderIsAttachedWhenAuthenticationIsSuccessful() throws IOException, ServletException
    {
        setUpSuccessWithJwtQueryStringParameter(successResponse());
        filter.doFilter(request, response, chain);

        verify(response, never()).addHeader(eq(WWW_AUTHENTICATE), any(String.class)); // because the OAuth filter adds this header but it's unnecessary for JWT
    }

    @Test
    public void requestIsFlaggedAsJwtIfJwtQueryStringParameterIsPresent() throws IOException, ServletException
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        setUpSuccessWithJwtQueryStringParameter(successResponse());
        filter.doFilter(request, response, chain);

        verify(request).setAttribute(JwtUtil.JWT_REQUEST_FLAG, true);
    }

    @Test
    public void requestIsFlaggedAsJwtIfJwtAuthorizationHeaderIsPresent() throws IOException, ServletException
    {
        setUpSuccessThoughJwtAuthHeader();
        filter.doFilter(request, response, chain);

        verify(request).setAttribute(JwtUtil.JWT_REQUEST_FLAG, true);
    }

    @Test
    public void requestIsNotFlaggedAsJwtIfNeitherJwtQueryStringParameterNorAuthHeaderArePresent() throws IOException, ServletException
    {
        setUpSuccessWithoutJwt();
        filter.doFilter(request, response, chain);

        verify(request, never()).setAttribute(JwtUtil.JWT_REQUEST_FLAG, true);
    }

    @Test
    public void authenticationControllerIsNotifiedAndFilterChainContinuesWhenAuthenticationIsSuccessfulAndJwtAuthHeaderIsValid() throws IOException, ServletException
    {
        when(request.getHeaders(JwtUtil.AUTHORIZATION_HEADER)).thenReturn(validJwtAuthHeaders());
        Authenticator.Result.Success success = successResponse();
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(success);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationSuccess(eq(success), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verify(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
    }

    @Test
    public void weStopTheFilterChainAndReportFailureIfAuthenticationFails() throws Exception
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        Authenticator.Result.Failure failure = failureResponse();
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(failure);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationFailure(eq(failure), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(chain);
    }

    @Test
    public void verifyThatNoWwwAuthenticateHeaderIsAttachedWhenAuthenticationFails() throws IOException, ServletException
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        Authenticator.Result.Failure failure = failureResponse();
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(failure);
        filter.doFilter(request, response, chain);

        verify(response, never()).addHeader(eq(WWW_AUTHENTICATE), any(String.class)); // because the OAuth filter adds this header but it's unnecessary for JWT
    }

    @Test
    public void verifyThatWeStopTheFilterChainAndReportFailureIfThereIsAnErrorDuringAuthentication() throws Exception
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        Authenticator.Result.Error error = errorResponse();
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(error);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationError(eq(error), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(chain);
    }

    @Test
    public void verifyThatNoWwwAuthenticateHeaderIsAttachedIfThereIsAnErrorDuringAuthentication() throws IOException, ServletException
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        Authenticator.Result.Error error = errorResponse();
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(error);
        filter.doFilter(request, response, chain);

        verify(response, never()).addHeader(eq(WWW_AUTHENTICATE), any(String.class)); // because the OAuth filter adds this header but it's unnecessary for JWT
    }

    @Test
    public void verifyThatWhenJwtParametersAreNotPresentWeLetTheRequestPassThrough() throws Exception
    {
        filter.doFilter(request, response, chain);

        verify(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verify(authenticationListener).authenticationNotAttempted(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(authenticator);
    }

    private void setUpSuccessThoughJwtAuthHeader()
    {
        when(request.getHeaders(JwtUtil.AUTHORIZATION_HEADER)).thenReturn(validJwtAuthHeaders());
        setUpSuccessWithoutJwt();
    }

    private Enumeration<String> validJwtAuthHeaders()
    {
        Vector<String> authHeaders = new Vector<String>();
        authHeaders.add(JwtUtil.JWT_AUTH_HEADER_PREFIX + MOCK_JWT);
        return authHeaders.elements();
    }

    private void setUpSuccessWithoutJwt()
    {
        setUpSuccessfulAuthResponse(successResponse());
    }

    private void setUpSuccessWithJwtQueryStringParameter(Authenticator.Result.Success success)
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(MOCK_JWT);
        setUpSuccessfulAuthResponse(success);
    }

    private void setUpSuccessfulAuthResponse(Authenticator.Result.Success success)
    {
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(success);
    }

    private Authenticator.Result.Failure failureResponse()
    {
        return new Authenticator.Result.Failure(createMessage("failure"));
    }

    private Authenticator.Result.Error errorResponse()
    {
        return new Authenticator.Result.Error(createMessage("error"));
    }

    private Authenticator.Result.Success successResponse()
    {
        return new Authenticator.Result.Success(createMessage("success"), new Principal()
        {
            @Override
            public String getName()
            {
                return "username";
            }
        });
    }

    private static Message createMessage(final String message)
    {
        return new Message()
        {
            @Override
            public String getKey()
            {
                return message;
            }

            @Override
            public Serializable[] getArguments()
            {
                return null;
            }
        };
    }
}
