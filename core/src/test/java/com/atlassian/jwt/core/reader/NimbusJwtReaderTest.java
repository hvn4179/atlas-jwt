package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.core.*;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.JOSEException;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Collections;
import java.util.Map;

import static com.atlassian.jwt.core.JsonUtils.assertJsonContainsOnly;
import static org.mockito.Mockito.when;

import static com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder.NO_REQUIRED_CLAIMS;

@RunWith(MockitoJUnitRunner.class)
public class NimbusJwtReaderTest
{
    private static final String SECRET_KEY = StringUtils.repeat("secret", 10);
    private static final int TIMESTAMP = 1300819380;
    private static final int TEN_MINS_EARLIER = TIMESTAMP - 60 * 10;
    private static final int ONE_HOUR_EARLIER = TIMESTAMP - 60 * 60;

    private static final long TIMESTAMP_MS = TIMESTAMP * 1000L;
    private static final Clock CLOCK = new StaticClock(TIMESTAMP_MS);

    private final HmacJwtSigner signer = new HmacJwtSigner(SECRET_KEY);

    @Mock
    private JwtConfiguration jwtConfiguration;

    @Before
    public void before()
    {
        when(jwtConfiguration.getMaxJwtLifetime()).thenReturn(60 * 60 * 1000L);
    }

    @Test
    public void canReadCorrectly() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        String payload = createNimbusHmac256JwtReader().read(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void iatIsRequired() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().read(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void expIsRequired() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().read(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void maxLifetimeExceeded() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", ONE_HOUR_EARLIER - 1, // max lifetime defaults to one hour
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().read(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test
    public void exactlyMaxLifetime() throws Exception
    {
        int oneHourEarlier = TIMESTAMP - 60 * 60;
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", oneHourEarlier, // max lifetime defaults to one hour
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        String payload = createNimbusHmac256JwtReader().read(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP,
                "iat", oneHourEarlier,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
    }

    @Test(expected = JwtSignatureMismatchException.class)
    public void incorrectSharedSecret() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        new NimbusHmac256JwtReader("wrong secret", jwtConfiguration, CLOCK).read(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtExpiredException.class)
    public void expiredJwtIsRejected() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        new NimbusHmac256JwtReader(SECRET_KEY, jwtConfiguration, new StaticClock(TIMESTAMP_MS + 1)).read(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtParseException.class)
    public void garbledJwtIsRejected() throws JwtParseException, JwtVerificationException
    {
        createNimbusHmac256JwtReader().read("easy.as.abc", NO_REQUIRED_CLAIMS);
    }

    // replace the payload with a slightly different payload, leaving the header and signature untouched
    @Test(expected = JwtSignatureMismatchException.class)
    public void tamperedJwtIsRejected() throws InterruptedException, JOSEException, JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        String altJwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "adminjoe" // spoof username
        );

        String[] jwtSegments = jwt.split("\\.");
        String[] altJwtSegments = altJwt.split("\\.");

        String forgedJwt = StringUtils.join(new String[]{jwtSegments[0], altJwtSegments[1], jwtSegments[2]}, ".");

        createNimbusHmac256JwtReader().read(forgedJwt, NO_REQUIRED_CLAIMS);
    }

    @Test
    public void correctlySupplyingRequiredClaimsResultsInNoVerificationExceptions() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "expectedClaim", "requiredValue",
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap("expectedClaim", (JwtClaimVerifier) new JwtClaimEqualityVerifier("requiredValue"));
        createNimbusHmac256JwtReader().read(jwt, requiredClaims);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void omittingARequiredClaimResultsInAVerificationException() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                // missing "expectedClaim"
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap("expectedClaim", (JwtClaimVerifier) new JwtClaimEqualityVerifier("requiredValue"));
        createNimbusHmac256JwtReader().read(jwt, requiredClaims);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void anInCorrectValueForARequiredClaimResultsInAVerificationException() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "expectedClaim", "totally wrong value",
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap("expectedClaim", (JwtClaimVerifier) new JwtClaimEqualityVerifier("requiredValue"));
        createNimbusHmac256JwtReader().read(jwt, requiredClaims);
    }

    @Test
    public void signedClaimVerifierVerifiesItsCorrectlySignedClaim() throws JwtParseException, JwtVerificationException
    {
        JwtReader reader = createNimbusHmac256JwtReader();
        String signingInput = "signing input";
        String claimName = "expectedSignedClaim";
        JwtClaimVerifier signedClaimVerifier = reader.createSignedClaimVerifier(signingInput, claimName);
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                claimName, signer.signHmac256(signingInput),
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap(claimName, signedClaimVerifier);
        reader.read(jwt, requiredClaims);
    }

    @Test(expected = JwtSignatureMismatchException.class)
    public void signedClaimVerifierRejectsAnIncorrectlySignedClaim() throws JwtParseException, JwtVerificationException
    {
        JwtReader reader = createNimbusHmac256JwtReader();
        String signingInput = "signing input";
        String claimName = "expectedSignedClaim";
        JwtClaimVerifier signedClaimVerifier = reader.createSignedClaimVerifier(signingInput, claimName);
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                claimName, "bad signature",
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap(claimName, signedClaimVerifier);
        reader.read(jwt, requiredClaims);
    }

    private JwtReader createNimbusHmac256JwtReader()
    {
        return new NimbusHmac256JwtReader(SECRET_KEY, jwtConfiguration, CLOCK);
    }
}
