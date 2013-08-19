package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.JwtConfiguration;
import com.atlassian.jwt.core.StaticClock;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class NimbusJwtReaderTest
{
    public static final String PASSWORD = "secret";

    private JwtReader reader;

    @Mock
    private JwtConfiguration jwtConfiguration;

    @Before
    public void before()
    {
        when(jwtConfiguration.getMaxJwtLifetime()).thenReturn(60 * 60 * 1000L);

        reader = new NimbusJwtReader(new MACVerifier(PASSWORD), jwtConfiguration);
    }

    // manually verified by running the generated JWT through Google jsontoken
    @Test
    @Ignore // need to regenerate token with iad & exp
    public void canReadCorrectly() throws JwtParseException, JwtVerificationException
    {
        String json = "{\"exp\":1300819380,"
                + "\"http:\\/\\/example.com\\/is_root\":true,"
                + "\"iss\":\"joe\"}";
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
        assertThat(new NimbusJwtReader(new MACVerifier(PASSWORD), jwtConfiguration, new StaticClock(new Date(1300819380 - 1))).verify(jwt).getJsonPayload(), is(json));
    }

    // manually verified by running the generated JWT through Google jsontoken
    @Test(expected = JwtInvalidClaimException.class)
    public void iadAndExpAreRequired() throws JwtParseException, JwtVerificationException
    {
        String json = "{\"exp\":1300819380,"
                + "\"http:\\/\\/example.com\\/is_root\":true,"
                + "\"iss\":\"joe\"}";
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
        assertThat(new NimbusJwtReader(new MACVerifier(PASSWORD), jwtConfiguration, new StaticClock(new Date(1300819380 - 1))).verify(jwt).getJsonPayload(), is(json));
    }

    @Test(expected = JwtSignatureMismatchException.class)
    public void wrongPasswordIsDetected() throws JwtParseException, JwtVerificationException
    {
        String json = "{\"exp\":1300819380,"
                + "\"http:\\/\\/example.com\\/is_root\":true,"
                + "\"iss\":\"joe\"}";
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
        assertThat(new NimbusJwtReader(new MACVerifier("wrong password"), jwtConfiguration).verify(jwt).getJsonPayload(), is(json));
    }

    @Test(expected = JwtExpiredException.class)
    public void expiredJwtIsRejected() throws JOSEException, InterruptedException, JwtParseException, JwtVerificationException
    {
        reader.verify(createExpiredJwt().serialize());
    }

    // replace the payload with a slightly different payload
    // while leaving the header and signature untouched
    @Test(expected = JwtSignatureMismatchException.class)
    public void tamperedJwtIsRejected() throws InterruptedException, JOSEException, JwtParseException, JwtVerificationException
    {
        JWSObject jwt = createJwt(1000l * 60 * 60, 0);
        String original = jwt.serialize();
        JSONObject payloadJson = jwt.getPayload().toJSONObject();
        payloadJson.put("claim", "fraudulent");
        jwt = new JWSObject((JWSHeader) jwt.getHeader(), new Payload(payloadJson));
        jwt.sign(new MACSigner("irrelevant"));
        String newSerializedJwt = jwt.serialize();
        String originalHeader = original.substring(0, original.indexOf('.'));
        String originalSignature = original.substring(original.lastIndexOf('.') + 1);
        String newEncodedPayload = newSerializedJwt.substring(newSerializedJwt.indexOf('.') + 1, newSerializedJwt.lastIndexOf('.'));
        String composite = originalHeader + '.' + newEncodedPayload + '.' + originalSignature;
        reader.verify(composite);
    }

    @Test(expected = JwtParseException.class)
    public void garbledJwtIsRejected() throws JwtParseException, JwtVerificationException
    {
        reader.verify("abc.123.def");
    }

    private JWSObject createExpiredJwt() throws InterruptedException, JOSEException
    {
        return createJwt(1, -1000);
    }

    private JWSObject createJwt(long expiryDuration, long clockOffset) throws JOSEException, InterruptedException
    {
        // Compose the JWT claims set
        JWTClaimsSet jwtClaims = new JWTClaimsSet();
        jwtClaims.setIssuer("https://openid.net");
        jwtClaims.setSubject("alice");
        List<String> aud = new ArrayList<String>();
        aud.add("https://app-one.com");
        aud.add("https://app-two.com");
        jwtClaims.setAudience(aud);
        Date now = new Date(System.currentTimeMillis() + clockOffset);
        jwtClaims.setExpirationTime(new Date(now.getTime() + expiryDuration));
        jwtClaims.setNotBeforeTime(now);
        jwtClaims.setIssueTime(now);
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        jwtClaims.setClaim("claim", "genuine");

        // Create payload
        Payload payload = new Payload(jwtClaims.toJSONObject());

        // Create JWS header with HS256 algorithm
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        header.setType(new JOSEObjectType("JWT"));

        // Create JWS object
        JWSObject jwsObject = new JWSObject(header, payload);

        // Create HMAC signer
        JWSSigner signer = new MACSigner(PASSWORD);
        jwsObject.sign(signer);

        return jwsObject;
    }
}
