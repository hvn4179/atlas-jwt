package com.atlassian.jwt.plugin.servlet;

import com.atlassian.jwt.plugin.JwtUtil;
import com.atlassian.sal.api.ApplicationProperties;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.AuthenticationListener;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.security.Principal;

import static junit.framework.Assert.fail;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthFilterTest
{
    private static final String VALID_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
    public static final String ADD_ON_SERVICE_ACCOUNT = "add-on service account";
    public static final Principal ADD_ON_PRINCIPAL = new Principal()
    {
        @Override
        public String getName()
        {
            return ADD_ON_SERVICE_ACCOUNT;
        }
    };

    Filter filter;

    @Mock
    Authenticator authenticator;
    @Mock
    AuthenticationListener authenticationListener;
    @Mock
    AuthenticationController authenticationController;
    @Mock
    ApplicationProperties applicationProperties;
    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;
    @Mock
    FilterChain chain;

    @Before
    public void setUp()
    {
        filter = new JwtAuthFilter(authenticationListener, authenticator, authenticationController);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://host/service"));
        when(request.getRequestURI()).thenReturn("/service");
        when(request.getMethod()).thenReturn("GET");
        when(request.getParameter(JwtUtil.JWT_PARAM_NAME)).thenReturn(VALID_JWT);
        when(request.getContextPath()).thenReturn("");
    }

    @Test
    public void verifyThatAuthenticationControllerIsNotifiedAndFilterChainContinuesWhenAuthenticationIsSuccessful() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(true);
        Authenticator.Result.Success success = new Authenticator.Result.Success(createMessage("success"), ADD_ON_PRINCIPAL);
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(success);

        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationSuccess(eq(success), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verify(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
    }

    @Test
    public void verifyThatOnSuccessfulAuthenticationTheJwtPayloadIsAttached()
    {
        fail("TODO");
    }

    @Test
    public void verifyThatWeStopTheFilterChainAndReportFailureIfAuthenticationFails() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(true);
        Authenticator.Result.Failure failure = new Authenticator.Result.Failure(createMessage("failure"));
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(failure);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationFailure(eq(failure), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(chain);
    }

    @Test
    public void verifyThatWeStopTheFilterChainAndReportFailureIfThereIsAnErrorDuringAuthentication() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(true);
        Authenticator.Result.Error error = new Authenticator.Result.Error(createMessage("error"));
        when(authenticator.authenticate(isA(HttpServletRequest.class), isA(HttpServletResponse.class))).thenReturn(error);
        filter.doFilter(request, response, chain);

        verify(authenticationListener).authenticationError(eq(error), isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(chain);
    }

    @Test
    public void verifyThatWhenOAuthParametersAreNotPresentWeLetTheRequestPassThru() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(true);
        when(request.getParameter(JwtUtil.JWT_PARAM_NAME)).thenReturn(null);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verify(response, never()).addHeader(eq("WWW-Authenticate"), startsWith("OAuth"));
        verify(authenticationListener).authenticationNotAttempted(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
        verifyNoMoreInteractions(authenticationListener);
        verifyZeroInteractions(authenticator);
    }

    @Test
    public void verifyWWWAuthenticateHeaderAddedWhenStatusIsSetToUnauthorizedWithoutAMessage() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(false);
        doAnswer(new FilterChainInvocation()
        {
            protected void chainInvoked(HttpServletRequest request, HttpServletResponse response)
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }).when(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        filter.doFilter(request, response, chain);

        verify(response).addHeader(eq("WWW-Authenticate"), startsWith("OAuth"));
    }

    @Test
    public void verifyWWWAuthenticateHeaderAddedWhenStatusIsSetToUnauthorizedWithAMessage() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(false);
        doAnswer(new FilterChainInvocation()
        {
            @SuppressWarnings("deprecation")
            protected void chainInvoked(HttpServletRequest request, HttpServletResponse response)
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED, "Denied, Sucka!");
            }
        }).when(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        filter.doFilter(request, response, chain);

        verify(response).addHeader(eq("WWW-Authenticate"), startsWith("OAuth"));
    }

    @Test
    public void verifyWWWAuthenticateHeaderAddedWhenUnauthorizedErrorIsSentWithoutAMessage() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(false);
        doAnswer(new FilterChainInvocation()
        {
            protected void chainInvoked(HttpServletRequest request, HttpServletResponse response) throws IOException
            {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }).when(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        filter.doFilter(request, response, chain);

        verify(response).addHeader(eq("WWW-Authenticate"), startsWith("OAuth"));
    }

    @Test
    public void verifyWWWAuthenticateHeaderAddedWhenUnauthorizedErrorIsSentWithAMessage() throws Exception
    {
        when(authenticationController.shouldAttemptAuthentication(request)).thenReturn(false);
        doAnswer(new FilterChainInvocation()
        {
            protected void chainInvoked(HttpServletRequest request, HttpServletResponse response) throws IOException
            {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Denied, Sucka!");
            }
        }).when(chain).doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));

        filter.doFilter(request, response, chain);

        verify(response).addHeader(eq("WWW-Authenticate"), startsWith("OAuth"));
    }

    private static abstract class FilterChainInvocation implements Answer<Object>
    {
        public Object answer(InvocationOnMock invocation) throws Throwable
        {
            HttpServletRequest request = (HttpServletRequest) invocation.getArguments()[0];
            HttpServletResponse response = (HttpServletResponse) invocation.getArguments()[1];
            chainInvoked(request, response);
            return null;
        }

        protected abstract void chainInvoked(HttpServletRequest request, HttpServletResponse response) throws IOException;
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
