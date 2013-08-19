package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.core.HmacJwtSigner;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

import static com.atlassian.jwt.core.JsonUtils.assertJsonContainsOnly;

/**
 *
 */
public class NimbusUnverifiedJwtReaderTest
{
    private static final String SECRET_KEY = StringUtils.repeat("secret", 10);

    private final HmacJwtSigner signer = new HmacJwtSigner(SECRET_KEY);

    @Test
    public void readWithoutVerification() throws Exception
    {
        String jwt = signer.jsonToHmacSha256Jwt(
            "exp", 100000,
            "iat", 500,
            "\"http:\\/\\/example.com\\/is_root\"", true,
            "iss", "the_king_of_france"
        );
        String payload = new NimbusUnverifiedJwtReader().parse(jwt).getJsonPayload();
        assertJsonContainsOnly(payload,
            "exp", 100000,
            "iat", 500,
            "\"http:\\/\\/example.com\\/is_root\"", true,
            "iss", "the_king_of_france"
        );
    }

}
