package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.core.JwtConfiguration;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.HmacJwtSigner;
import com.atlassian.jwt.core.StaticClock;
import com.atlassian.jwt.exception.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Date;

import static com.atlassian.jwt.core.JsonUtils.assertJsonContainsOnly;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class NimbusJwtReaderTest
{
    private static final String SECRET_KEY = StringUtils.repeat("secret", 10);
    private static final int TIMESTAMP = 1300819380;
    private static final int TEN_MINS_EARLIER = TIMESTAMP - 60 * 10;
    private static final int ONE_HOUR_EARLIER = TIMESTAMP - 60 * 60;

    private static final long TIMESTAMP_MS = TIMESTAMP * 1000L;
    private static final Clock CLOCK = new StaticClock(new Date(TIMESTAMP_MS));

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
        String payload = new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(jwt).getJsonPayload();
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
        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(jwt);
    }

    @Test(expected = JwtInvalidClaimException.class)
    public void expIsRequired() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
                "iat", TEN_MINS_EARLIER,
                "\"http:\\/\\/example.com\\/is_root\"", true,
                "iss", "joe"
        );
        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(jwt);
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
        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(jwt);
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
        String payload = new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(jwt).getJsonPayload();
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
        new NimbusJwtReader(new MACVerifier("wrong secret"), jwtConfiguration, CLOCK).verify(jwt);
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
        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, new StaticClock(new Date(TIMESTAMP_MS + 1))).verify(jwt);
    }

    @Test(expected = JwtParseException.class)
    public void garbledJwtIsRejected() throws JwtParseException, JwtVerificationException
    {
        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify("easy.as.abc");
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

        String forgedJwt = StringUtils.join(new String[] {jwtSegments[0], altJwtSegments[1], jwtSegments[2]}, ".");

        new NimbusJwtReader(new MACVerifier(SECRET_KEY), jwtConfiguration, CLOCK).verify(forgedJwt);
    }

}
