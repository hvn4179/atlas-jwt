package com.atlassian.jwt.core;

import com.atlassian.jwt.JwtWriter;
import com.atlassian.jwt.exception.JwtSigningException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class NimbusJwtWriterTest
{
    public static final JWSAlgorithm ALGORITHM = JWSAlgorithm.HS256;
    public static final String PASSWORD = "secret";

    private JwtWriter writer;

    @Before
    public void before()
    {
        writer = new NimbusJwtWriter(ALGORITHM, new MACSigner(PASSWORD));
    }

    // manually verified by running the generated JWT through Google jsontoken
    @Test
    public void canWriteCorrectly() throws JwtSigningException
    {
        String json = "{\"iss\":\"joe\",\n"
                    + " \"exp\":1300819380,\n"
                    + " \"http://example.com/is_root\":true}";
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
        assertThat(writer.jsonToJwt(json), is(jwt));
    }
}
