package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.core.JsonUtils;
import org.junit.Test;

/**
 *
 */
public class JsonSmartJwtJsonBuilderTest
{
    private static final int EXP = 1300819380;
    public static final int NBF = EXP - 30 * 60;
    private static final int IAT = EXP - 60 * 60;
    private static final String ISS = "Atlassian Software";
    private static final String AUD = "world";
    private static final String SUB = "sports law";
    public static final String TYP = "type a";
    public static final String JTI = "abc123";
    public static final String CUSTOM_KEY = "custom";
    public static final String CUSTOM_VALUE = "motsuc";


    @Test
    public void claimGeneration() throws Exception
    {
        String json = new JsonSmartJwtJsonBuilderFactory().jsonBuilder()
            .audience(AUD)
            .claim(CUSTOM_KEY, CUSTOM_VALUE)
            .expirationTime(EXP)
            .issuedAt(IAT)
            .issuer(ISS)
            .jwtId(JTI)
            .notBefore(NBF)
            .subject(SUB)
            .type(TYP)
            .build();

        JsonUtils.assertJsonContainsOnly(json,
            "aud", AUD,
            CUSTOM_KEY, CUSTOM_VALUE,
            "exp", EXP,
            "iat", IAT,
            "iss", ISS,
            "jti", JTI,
            "nbf", NBF,
            "sub", SUB,
            "typ", TYP
        );
    }

}
