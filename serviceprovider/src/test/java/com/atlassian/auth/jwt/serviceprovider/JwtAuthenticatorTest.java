package com.atlassian.auth.jwt.serviceprovider;

import com.atlassian.auth.jwt.core.JwtIssuerToAccountNameMapper;
import com.atlassian.auth.jwt.core.NimbusMacJwtReader;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.when;

/**
 * Author: pbrownlow
 * Date: 5/08/13
 * Time: 4:57 PM
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticatorTest
{
    private static final String VALID_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
    private static final long JWT_EXPIRY_TIME = 1300819380000L;
    private static final String ADD_ON_SERVICE_ACCOUNT = "add-on service account username";
    private static final Principal ADD_ON_PRINCIPAL = new Principal()
    {
        @Override
        public String getName()
        {
            return ADD_ON_SERVICE_ACCOUNT;
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj instanceof Principal)
            {
                Principal otherPrincipal = (Principal) obj;
                return getName().equals(otherPrincipal.getName());
            }

            return false;
        }
    };
    private static final String SHARED_SECRET = "secret";

    private Authenticator authenticator;

    @Mock AuthenticationController authenticationController;
    @Mock
    JwtIssuerToAccountNameMapper issuerToAccountNameMapper;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;

    @Before
    public void setUp() throws IOException
    {
        authenticator = createAuthenticator(-1);

        when(request.getRequestURL()).thenReturn(new StringBuffer("http://host/service"));
        when(request.getRequestURI()).thenReturn("/service");
        when(request.getMethod()).thenReturn("GET");

        when(issuerToAccountNameMapper.get("joe")).thenReturn(ADD_ON_SERVICE_ACCOUNT);

        when(authenticationController.canLogin(ADD_ON_PRINCIPAL, request)).thenReturn(true);
    }

    @Test
    public void validJwtResultsInSuccess()
    {
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(VALID_JWT);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void validJwtResultsInCorrectPrincipal()
    {
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(VALID_JWT);
        assertThat(authenticator.authenticate(request, response).getPrincipal().getName(), is(ADD_ON_SERVICE_ACCOUNT));
    }

    @Test
    public void validJwtWithPrincipalWhoCannotLogInResultsInFailure()
    {
        when(authenticationController.canLogin(ADD_ON_PRINCIPAL, request)).thenReturn(false);
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(VALID_JWT);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullJwtResultsInException()
    {
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(null);
        authenticator.authenticate(request, response);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyStringJwtResultsInException()
    {
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn("");
        authenticator.authenticate(request, response);
    }

    @Test
    public void garbledJwtResultsInError()
    {
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn("abc.123.def");
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.ERROR));
    }

    @Test
    public void badJwtSignatureResultsInFailure()
    {
        String badJwt = VALID_JWT.substring(0, VALID_JWT.lastIndexOf('.') + 1) + "bad_signature";
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(badJwt);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void expiredJwtResultsInFailure()
    {
        authenticator = createAuthenticator(1);
        when(request.getParameter(JwtUtils.JWT_PARAM_NAME)).thenReturn(VALID_JWT);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    private JwtAuthenticator createAuthenticator(long clockOffsetMillis)
    {
        return new JwtAuthenticator(new NimbusMacJwtReader(SHARED_SECRET, new StaticClock(new Date(JWT_EXPIRY_TIME + clockOffsetMillis))), issuerToAccountNameMapper, authenticationController);
    }
}
