package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.applinks.exception.NotAJwtPeerException;
import com.atlassian.jwt.core.HttpRequestCanonicalizer;
import com.atlassian.jwt.core.reader.NimbusMacJwtReader;
import com.atlassian.jwt.core.writer.NimbusJwtWriter;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.httpclient.CanonicalHttpServletRequest;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.sal.api.auth.Authenticator;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.NotImplementedException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import static com.atlassian.jwt.JwtConstants.HttpRequests.AUTHORIZATION_HEADER;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticatorImplTest
{
    private static final String ADD_ON_USER_KEY = "add-on user key";
    private static final String END_USER_ACCOUNT_NAME = "end user";
    private static final Principal ADD_ON_PRINCIPAL = new Principal()
    {
        @Override
        public String getName()
        {
            return ADD_ON_USER_KEY;
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

    private static final String PROTOCOL = "http";
    private static final String HOST = "host";
    private static final int PORT = 80;

    private JwtAuthenticatorImpl authenticator;

    private @Mock CrowdService crowdService;
    private @Mock JwtApplinkFinder jwtApplinkFinder;
    private @Mock ApplicationLink applicationLink;
    private @Mock User addOnUser;

    private final static JwtService jwtService = new JwtService()
    {
        @Override
        public boolean isJwtPeer(ApplicationLink applicationLink)
        {
            throw new NotImplementedException();
        }

        @Override
        public ApplinkJwt verifyJwt(final String jwtString, Map<String, ? extends JwtClaimVerifier> claimVerifiers) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
        {
            final Jwt jwt = new NimbusMacJwtReader(SHARED_SECRET).readAndVerify(jwtString, claimVerifiers);

            if (!JWT_ISSUER.equals(jwt.getIssuer()))
            {
                throw new JwtUnknownIssuerException(jwt.getIssuer());
            }

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
    };
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;

    boolean impersonationEnabled;

    @Before
    public void setUp() throws IOException
    {
        impersonationEnabled = Boolean.getBoolean(JwtConstants.AppLinks.SYS_PROP_ALLOW_IMPERSONATION);
        authenticator = new JwtAuthenticatorImpl(jwtService);

        setUpRequestUrl(request, PROTOCOL, HOST, PORT, URI);
        when(request.getMethod()).thenReturn(METHOD);
        when(request.getHeaders(AUTHORIZATION_HEADER)).thenReturn(new StringTokenizer(""));
        when(request.getParameterMap()).thenReturn(PARAMETERS_WITHOUT_JWT);
        when(jwtApplinkFinder.find(JWT_ISSUER)).thenReturn(applicationLink);
        when(applicationLink.getProperty(JwtConstants.AppLinks.ADD_ON_USER_KEY_PROPERTY_NAME)).thenReturn(ADD_ON_USER_KEY);
        when(crowdService.getUser(ADD_ON_PRINCIPAL.getName())).thenReturn(addOnUser);
        when(addOnUser.isActive()).thenReturn(true);
    }

    @After
    public void cleanup()
    {
        System.setProperty(JwtConstants.AppLinks.SYS_PROP_ALLOW_IMPERSONATION, Boolean.toString(impersonationEnabled));
    }

    @Test
    public void validJwtResultsInSuccess() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        Authenticator.Result result = authenticator.authenticate(request, response);
        assertThat(result.getMessage(), result.getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void validJwtDoesNotResultInSentErrorCode() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        authenticator.authenticate(request, response);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void validJwtResultsInCorrectPrincipal() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        assertThat(authenticator.authenticate(request, response).getPrincipal(), is(nullValue()));
    }

    @Test
    public void unknownIssuerResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createValidJwtWithIssuer("bad issuer"));
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void nullJwtResultsInInternalServerErrorResponseCode() throws IOException
    {
        setUpJwtQueryParameter(null);
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_INTERNAL_SERVER_ERROR), anyString());
    }

    @Test
    public void emptyStringJwtResultsInInternalServerErrorResponseCode() throws IOException
    {
        setUpJwtQueryParameter("");
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_INTERNAL_SERVER_ERROR), anyString());
    }

    @Test
    public void garbledJwtResultsInError()
    {
        setUpJwtQueryParameter("just.plain.wrong");
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.ERROR));
    }

    @Test
    public void garbledJwtResultsInBadRequestResponseCode() throws IOException
    {
        setUpJwtQueryParameter("just.plain.wrong");
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_BAD_REQUEST), anyString());
    }

    @Test
    public void badJwtSignatureResultsInFailure() throws IOException, NoSuchAlgorithmException
    {
        String validJwt = createValidJwt();
        String badJwt = validJwt.substring(0, validJwt.lastIndexOf('.') + 1) + "bad_signature";
        setUpJwtQueryParameter(badJwt);
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void badJwtSignatureResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        String validJwt = createValidJwt();
        String badJwt = validJwt.substring(0, validJwt.lastIndexOf('.') + 1) + "bad_signature";
        setUpJwtQueryParameter(badJwt);
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void expiredJwtResultsInFailure() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createExpiredJwt());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void expiredJwtResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createExpiredJwt());
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void almostExpiredJwtResultsInSuccess() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        JWTClaimsSet claims = createExpiredClaims();
        claims.setExpirationTime(new Date(claims.getExpirationTime().getTime() + 1000));
        setUpJwtQueryParameter(createExpiredJwt());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void notBeforeTimeInTheFutureResultsInFailure() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createJwtWithNotBeforeTimeInTheFuture());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void notBeforeTimeInTheFutureResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createJwtWithNotBeforeTimeInTheFuture());
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void tamperingWithTheMethodResultsInFailure() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        when(request.getMethod()).thenReturn(METHOD.equals("GET") ? "POST" : "GET"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheMethodResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        when(request.getMethod()).thenReturn(METHOD.equals("GET") ? "POST" : "GET"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void tamperingWithTheUriResultsInFailure() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        when(request.getRequestURI()).thenReturn("/tampered"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheUriResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        when(request.getRequestURI()).thenReturn("/tampered"); // important: tamper with the request AFTER setting up the valid JWT query parameter
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void tamperingWithTheQueryParametersResultsInFailure() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        Map<String, String[]> editedParams = new HashMap<String, String[]>(PARAMETERS_WITHOUT_JWT);
        editedParams.put("new", new String[]{"value"});
        when(request.getParameterMap()).thenReturn(editedParams); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void tamperingWithTheQueryParametersResultsInUnauthorisedResponseCode() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        Map<String, String[]> editedParams = new HashMap<String, String[]>(PARAMETERS_WITHOUT_JWT);
        editedParams.put("new", new String[]{"value"});
        when(request.getParameterMap()).thenReturn(editedParams); // important: tamper with the request AFTER setting up the valid JWT query parameter
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    @Test
    public void changingTheProtocolIsHarmless() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, "different protocol", HOST, PORT, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void changingTheHostIsHarmless() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, PROTOCOL, "different host", PORT, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void changingThePortIsHarmless() throws IOException, NoSuchAlgorithmException
    {
        setUpValidJwtQueryParameter();
        setUpRequestUrl(request, PROTOCOL, HOST, PORT + 1, URI); // important: tamper with the request AFTER setting up the valid JWT query parameter
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.SUCCESS));
    }

    @Test
    public void missingQueryParamsSigResultsInError()
    {
        setUpJwtQueryParameter(createJwtWithoutQuerySignature());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.ERROR));
    }

    @Test
    public void missingQueryParamsSigResultsInBadRequestResponseCode() throws IOException
    {
        setUpJwtQueryParameter(createJwtWithoutQuerySignature());
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_BAD_REQUEST), anyString());
    }

    @Test
    public void emptyStringQueryParamsSigResultsInFailure()
    {
        setUpJwtQueryParameter(createJwtWithEmptyStringQuerySignature());
        assertThat(authenticator.authenticate(request, response).getStatus(), is(Authenticator.Result.Status.FAILED));
    }

    @Test
    public void emptyStringQueryParamsSigResultsInUnauthorisedResponseCode() throws IOException
    {
        setUpJwtQueryParameter(createJwtWithEmptyStringQuerySignature());
        authenticator.authenticate(request, response);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
    }

    private String createJwtWithoutQuerySignature()
    {
        return JWT_WRITER.jsonToJwt(createJwtClaimsSetWithoutSignatures().toJSONObject().toJSONString());
    }

    private String createJwtWithEmptyStringQuerySignature()
    {
        JWTClaimsSet claims = createJwtClaimsSetWithoutSignatures();
        claims.setClaim(JwtConstants.Claims.QUERY_HASH, "");
        return JWT_WRITER.jsonToJwt(claims.toJSONObject().toJSONString());
    }

    private String createJwtWithNotBeforeTimeInTheFuture() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        JWTClaimsSet claims = createValidJwtClaimsSet();
        claims.setNotBeforeTime(new Date(System.currentTimeMillis() + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS * 1000 + 1000));
        return JWT_WRITER.jsonToJwt(claims.toJSONObject().toJSONString());
    }

    private String createExpiredJwt() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        return JWT_WRITER.jsonToJwt(createExpiredClaims().toJSONObject().toJSONString());
    }

    private JWTClaimsSet createExpiredClaims() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        JWTClaimsSet claims = createValidJwtClaimsSet();
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS * 1000 - 1000);
        claims.setExpirationTime(expirationTime);
        claims.setIssueTime(new Date(expirationTime.getTime() - 1));
        return claims;
    }

    private void setUpValidJwtQueryParameter() throws IOException, NoSuchAlgorithmException
    {
        setUpJwtQueryParameter(createValidJwt());
    }

    private void setUpJwtQueryParameter(String jwt)
    {
        when(request.getParameter(JwtConstants.JWT_PARAM_NAME)).thenReturn(jwt);
        Map<String, String[]> parameters = new HashMap<String, String[]>(PARAMETERS_WITHOUT_JWT);
        parameters.put(JwtConstants.JWT_PARAM_NAME, new String[]{jwt});
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
        return createJwtClaimsSetWithoutSignatures(JWT_ISSUER, END_USER_ACCOUNT_NAME);
    }

    private static JWTClaimsSet createJwtClaimsSetWithoutSignatures(String issuer, String subject)
    {
        JWTClaimsSet claims = new JWTClaimsSet();
        claims.setIssuer(issuer);
        Date now = new Date();
        claims.setIssueTime(now);
        claims.setExpirationTime(new Date(now.getTime() + 60 * 1000));
        claims.setNotBeforeTime(now);
        if (subject != null)
        {
            claims.setSubject(subject);
        }
        return claims;
    }

    private String createValidJwt() throws IOException, NoSuchAlgorithmException
    {
        return createValidJwt(JWT_ISSUER, END_USER_ACCOUNT_NAME);
    }

    private String createValidJwtWithIssuer(String issuer) throws IOException, NoSuchAlgorithmException
    {
        return createValidJwt(issuer, END_USER_ACCOUNT_NAME);
    }

    private String createValidJwtWithSubject(String subject) throws IOException, NoSuchAlgorithmException
    {
        return createValidJwt(JWT_ISSUER, subject);
    }

    private String createValidJwt(String issuer, String subject) throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        JWTClaimsSet claims = createValidJwtClaimsSet(issuer, subject);
        String jsonString = claims.toJSONObject().toJSONString();
        return JWT_WRITER.jsonToJwt(jsonString);
    }

    private JWTClaimsSet createValidJwtClaimsSet() throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        return createValidJwtClaimsSet(JWT_ISSUER, END_USER_ACCOUNT_NAME);
    }

    private JWTClaimsSet createValidJwtClaimsSet(String issuer, String subject) throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        JWTClaimsSet claims = createJwtClaimsSetWithoutSignatures(issuer, subject);
        claims.setClaim(JwtConstants.Claims.QUERY_HASH, HttpRequestCanonicalizer.computeCanonicalRequestHash(new CanonicalHttpServletRequest(request)));
        return claims;
    }
}
