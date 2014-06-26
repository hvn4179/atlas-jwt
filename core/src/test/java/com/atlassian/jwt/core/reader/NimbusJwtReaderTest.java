package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.HmacJwtSigner;
import com.atlassian.jwt.core.StaticClock;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.JOSEException;
import net.minidev.json.parser.ParseException;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Collections;
import java.util.Map;

import static com.atlassian.jwt.core.JsonUtils.assertJsonContainsOnly;
import static com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder.NO_REQUIRED_CLAIMS;

@RunWith(MockitoJUnitRunner.class)
public class NimbusJwtReaderTest
{
    private static final String SECRET_KEY = StringUtils.repeat("secret", 10);
    private static final int TIMESTAMP = 1300819380;
    private static final int TEN_MINS_EARLIER = TIMESTAMP - 60 * 10;

    private static final long TIMESTAMP_MS = TIMESTAMP * 1000L;
    private static final Clock CLOCK = new StaticClock(TIMESTAMP_MS);

    private final HmacJwtSigner signer = new HmacJwtSigner(SECRET_KEY);

    @Test
    public void canReadCorrectly() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1, // just barely on the good side of the "now" boundary
                "iat", TEN_MINS_EARLIER,
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS, // just barely on the good side of the "exp" boundary
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        String payload = createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1,
                "iat", TEN_MINS_EARLIER,
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
    }

    @Test
    public void sharedSecretIsIgnoredForNonVerifyingMode() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1, // just barely on the good side of the "now" boundary
                "iat", TEN_MINS_EARLIER,
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS, // just barely on the good side of the "exp" boundary
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        final String payload = new NimbusMacJwtReader("wrong secret", CLOCK).readUnverified(jwt).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1,
                "iat", TEN_MINS_EARLIER,
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS,
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
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void expIsRequired() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS);
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
        new NimbusMacJwtReader("wrong secret", CLOCK).readAndVerify(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test(expected = JwtExpiredException.class)
    public void expiredJwtIsRejected() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS, // the earliest time to be rejected
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        new NimbusMacJwtReader(SECRET_KEY, new StaticClock(TIMESTAMP_MS + 1)).readAndVerify(jwt, NO_REQUIRED_CLAIMS);
    }

    @Test
    public void notBeforeTimeInThePastIsAccepted() throws ParseException, JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe",
                "nbf", TIMESTAMP - 1
        );
        String payload = createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe",
                "nbf", TIMESTAMP - 1
        );
    }

    @Test
    public void notBeforeTimeThatIsRightNowPlusLeewayIsAccepted() throws ParseException, JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1, // just on the good side of the "nbf" boundary
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe",
                "nbf", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS // the latest time to be accepted
        );
        String payload = createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
        assertJsonContainsOnly(payload,
                "exp", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1,
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe",
                "nbf", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS
        );
    }

    @Test(expected = JwtTooEarlyException.class)
    public void notBeforeTimeThatIsInTheFutureIsRejected() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 2, // just on the good side of the "nbf" boundary
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe",
                "nbf", TIMESTAMP + JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1 // the earliest time to be rejected
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void equalExpiryAndNotBeforeTimesAreRejected() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "iat", TEN_MINS_EARLIER,
                "exp", TIMESTAMP,
                "nbf", TIMESTAMP,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void expiryTimeBeforeNotBeforeTimeIsRejected() throws JwtParseException, JwtVerificationException
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "iat", TEN_MINS_EARLIER,
                "exp", TIMESTAMP,
                "nbf", TIMESTAMP + 1,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    @Test(expected = JwtParseException.class)
    public void garbledJwtIsRejected() throws JwtParseException, JwtVerificationException
    {
        createNimbusHmac256JwtReader().readAndVerify("easy.as.abc", NO_REQUIRED_CLAIMS);
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

        createNimbusHmac256JwtReader().readAndVerify(forgedJwt, NO_REQUIRED_CLAIMS);
    }

    @Test
    public void correctlySupplyingRequiredClaimsResultsInNoVerificationExceptions() throws JwtParseException, JwtVerificationException
    {
        String claimName = "expectedClaim";
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                claimName, "requiredValue",
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap(claimName, (JwtClaimVerifier) new JwtClaimEqualityVerifier(claimName, "requiredValue"));
        createNimbusHmac256JwtReader().readAndVerify(jwt, requiredClaims);
    }

    @Test(expected = JwtMissingClaimException.class)
    public void omittingARequiredClaimResultsInAVerificationException() throws JwtParseException, JwtVerificationException
    {
        String claimName = "expectedClaim";
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                // missing "expectedClaim"
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap(claimName, (JwtClaimVerifier) new JwtClaimEqualityVerifier(claimName, "requiredValue"));
        createNimbusHmac256JwtReader().readAndVerify(jwt, requiredClaims);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void anIncorrectValueForARequiredClaimResultsInAVerificationException() throws JwtParseException, JwtVerificationException
    {
        String claimName = "expectedClaim";
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP,
                "iat", TEN_MINS_EARLIER,
                claimName, "totally wrong value",
                "iss", "joe"
        );
        Map<String, JwtClaimVerifier> requiredClaims = Collections.singletonMap(claimName, (JwtClaimVerifier) new JwtClaimEqualityVerifier(claimName, "requiredValue"));
        createNimbusHmac256JwtReader().readAndVerify(jwt, requiredClaims);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void reportsExpClaimWithStringValue() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", String.valueOf(TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1),
                "iat", TEN_MINS_EARLIER,
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void reportsIatClaimWithStringValue() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1,
                "iat", String.valueOf(TEN_MINS_EARLIER),
                "nbf", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS,
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void reportsNbfClaimWithStringValue() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "exp", TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS + 1,
                "iat", TEN_MINS_EARLIER,
                "nbf", String.valueOf(TIMESTAMP - JwtConstants.TIME_CLAIM_LEEWAY_SECONDS),
                "iss", "joe"
        );
        createNimbusHmac256JwtReader().readAndVerify(jwt, NO_REQUIRED_CLAIMS).getJsonPayload();
    }

    private JwtReader createNimbusHmac256JwtReader()
    {
        return new NimbusMacJwtReader(SECRET_KEY, CLOCK);
    }
}
