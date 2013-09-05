package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.applinks.exception.NotAJwtPeerException;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.SystemPropertyJwtConfiguration;
import com.atlassian.jwt.core.reader.NimbusMacJwtReader;
import com.atlassian.jwt.core.writer.NimbusJwtWriter;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.NotImplementedException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticatorTest
{
    private static final String END_USER_ACCOUNT_NAME = "end user";
    private static final Principal END_USER_PRINCIPAL = new Principal()
    {
        @Override
        public String getName()
        {
            return END_USER_ACCOUNT_NAME;
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
    private static final JWSSigner JWT_SIGNER = new MACSigner(SHARED_SECRET);
    private static final SigningAlgorithm SIGNING_ALGORITHM = SigningAlgorithm.HS256;
    private static final JwtWriter JWT_WRITER = new NimbusJwtWriter(SIGNING_ALGORITHM, JWT_SIGNER);
    private static final String JWT_ISSUER = "issuer";

    private static final String METHOD = "GET";
    private static final String URI = "/service";

    private static final Map<String, String[]> PARAMETERS_WITHOUT_JWT;
    static
    {
        PARAMETERS_WITHOUT_JWT = new HashMap<String, String[]>();
        PARAMETERS_WITHOUT_JWT.put("param-name", new String[]{"param-value"});
    }

    public static final String PROTOCOL = "http";
    public static final String HOST = "host";
    public static final int PORT = 80;

    @InjectMocks
    private JwtAuthenticator authenticator;

    @Mock AuthenticationController authenticationController;
    JwtService jwtService = new JwtService()
    {
        @Override
        public boolean isJwtPeer(ApplicationLink applicationLink)
        {
            throw new NotImplementedException();
        }

        @Override
        public ApplinkJwt verifyJwt(final String jwtString) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
        {
            final Jwt jwt = new NimbusMacJwtReader(SHARED_SECRET, new SystemPropertyJwtConfiguration()).verify(jwtString);

            return new ApplinkJwt()
            {
                @Override
                public Jwt getJwt()
                {
                    return jwt;
                }

                @Override
                public ApplicationLink getPeer()
                {
                    throw new NotImplementedException();
                }
            };
        }

        @Override
        public String issueJwt(String jsonPayload, ApplicationLink applicationLink) throws NotAJwtPeerException, JwtSigningException
        {
            throw new NotImplementedException();
        }

        @Override
        public String issueSignature(String signingInput, ApplicationLink applicationLink)
        {
            return new NimbusJwtWriter(SigningAlgorithm.HS256, new MACSigner(SHARED_SECRET)).sign(signingInput);
        }

        @Override
        public ApplicationLink getApplicationLink(Jwt jwt)
        {
            return mock(ApplicationLink.class);
        }
    };
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;

    @Before
    public void setUp() throws IOException
    {
        authenticator = new JwtAuthenticator(jwtService, authenticationController);

        setUpRequestUrl(request, PROTOCOL, HOST, PORT, URI);
        when(request.getMethod()).thenReturn(METHOD);
        when(request.getHeaders(JwtUtil.AUTHORIZATION_HEADER)).thenReturn(new StringTokenizer(""));
        when(request.getParameterMap()).thenReturn(PARAMETERS_WITHOUT_JWT);
        when(authenticationController.canLogin(END_USER_PRINCIPAL, request)).thenReturn(true);
    }

    @Test
    public void validJwtResultsInSuccess() throws IOException
    {
        setUpValidJwtQueryParameter();
        Authenticator.Result result = authenticator.authenticate(request, response);
        assertThat(result.getMessage(), result.getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void validJwtResultsInCorrectPrincipal() throws IOException
    {
        setUpValidJwtQueryParameter();
        assertThat(authenticator.authenticate(request, response).getPrincipal().getName(), is(END_USER_ACCOUNT_NAME));
    }

    @Test
    public void validJwtWithPrincipalWhoCannotLogInResultsInFailure() throws IOException
    {
        when(authenticationController.canLogin(END_USER_PRINCIPAL, request)).thenReturn(false);
        setUpValidJwtQueryParameter();
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullJwtResultsInException()
    {
        setUpJwtQueryParameter(null);
        authenticator.authenticate(request, response);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyStringJwtResultsInException()
    {
        setUpJwtQueryParameter("");
        authenticator.authenticate(request, response);
    }

    @Test
    public void garbledJwtResultsInError()
    {
        setUpJwtQueryParameter("just.plain.wrong");
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.ERROR));
    }

    @Test
    public void badJwtSignatureResultsInFailure() throws IOException
    {
        String validJwt = createValidJwt();
        String badJwt = validJwt.substring(0, validJwt.lastIndexOf('.') + 1) + "bad_signature";
        setUpJwtQueryParameter(badJwt);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void expiredJwtResultsInFailure()
    {
        setUpJwtQueryParameter(createExpiredJwt());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheMethodResultsInFailure() throws IOException
    {
        setUpValidJwtQueryParameter();
        when(request.getMethod()).thenReturn(METHOD.equals("GET") ? "POST" : "GET"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheUriResultsInFailure() throws IOException
    {
        setUpValidJwtQueryParameter();
        when(request.getRequestURI()).thenReturn("/tampered"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheQueryParametersResultsInFailure() throws IOException
    {
        setUpValidJwtQueryParameter();
        Map<String, String[]> editedParams = new HashMap<String, String[]>(PARAMETERS_WITHOUT_JWT);
        editedParams.put("new", new String[]{"value"});
        when(request.getParameterMap()).thenReturn(editedParams); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void changingTheProtocolIsHarmless() throws IOException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, "different protocol", HOST, PORT, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void changingTheHostIsHarmless() throws IOException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, PROTOCOL, "different host", PORT, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void changingThePortIsHarmless() throws IOException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, PROTOCOL, HOST, PORT + 1, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void missingQueryParamsSigResultsInFailure()
    {
        setUpJwtQueryParameter(createJwtWithoutQuerySignature());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void emptyStringQueryParamsSigResultsInFailure()
    {
        setUpJwtQueryParameter(createJwtWithEmptyStringQuerySignature());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    private String createJwtWithoutQuerySignature()
    {
        return JWT_WRITER.jsonToJwt(createJwtClaimsSetWithoutSignatures().toJSONObject().toJSONString());
    }

    private String createJwtWithEmptyStringQuerySignature()
    {
        JWTClaimsSet claims = createJwtClaimsSetWithoutSignatures();
        claims.setClaim(JwtConstants.Claims.QUERY_SIGNATURE, "");
        return JWT_WRITER.jsonToJwt(claims.toJSONObject().toJSONString());
    }

    private String createExpiredJwt()
    {
        JWTClaimsSet claims = createJwtClaimsSetWithoutSignatures();
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() - 1);
        claims.setExpirationTime(expirationTime);
        claims.setIssueTime(new Date(expirationTime.getTime() - 1));
        return JWT_WRITER.jsonToJwt(claims.toJSONObject().toJSONString());
    }

    private void setUpValidJwtQueryParameter() throws IOException
    {
        setUpJwtQueryParameter(createValidJwt());
    }

    private void setUpJwtQueryParameter(String jwt)
    {
        when(request.getParameter(JwtUtil.JWT_PARAM_NAME)).thenReturn(jwt);
        Map<String, String[]> parameters = new HashMap<String, String[]>(PARAMETERS_WITHOUT_JWT);
        parameters.put(JwtUtil.JWT_PARAM_NAME, new String[]{jwt});
        when(request.getParameterMap()).thenReturn(parameters);
    }

    private void setUpRequestUrl(HttpServletRequest request, String protocol, String host, int port, String Uri)
    {
        when(request.getRequestURL()).thenReturn(new StringBuffer(protocol + "://" + host + ":" + port + Uri));
        when(request.getProtocol()).thenReturn(protocol);
        when(request.getServerPort()).thenReturn(port);
        when(request.getRequestURI()).thenReturn(Uri);
    }

    private static JWTClaimsSet createJwtClaimsSetWithoutSignatures()
    {
        JWTClaimsSet claims = new JWTClaimsSet();
        claims.setIssuer(JWT_ISSUER);
        Date now = new Date();
        claims.setIssueTime(now);
        claims.setExpirationTime(new Date(now.getTime() + 60 * 1000));
        claims.setSubject(END_USER_ACCOUNT_NAME);
        return claims;
    }

    private String createValidJwt() throws IOException
    {
        JWTClaimsSet claims = createJwtClaimsSetWithoutSignatures();
        claims.setClaim(JwtConstants.Claims.QUERY_SIGNATURE, JWT_WRITER.sign(JwtUtil.canonicalizeQuery(request)));
        String jsonString = claims.toJSONObject().toJSONString();
        return JWT_WRITER.jsonToJwt(jsonString);
    }
}
