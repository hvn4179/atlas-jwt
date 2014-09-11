package com.atlassian.jwt.core.writer;

import com.atlassian.fugue.Either;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.HmacJwtSigner;
import com.atlassian.jwt.core.keys.KeyUtils;
import com.atlassian.jwt.exception.JwtSigningException;
import com.atlassian.jwt.writer.JwtWriter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.interfaces.RSAPrivateKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class NimbusJwtWriterTest
{
    private static final SigningAlgorithm ALGORITHM = SigningAlgorithm.HS256;
    private static final String SHARED_SECRET = "secret";

    private static final String PRIVATE_KEY_FILE_NAME = "private.pem";

    // manually verified by running the generated JWT through Google jsontoken
    @Test
    public void compareWrittenTokenToGoogleJsonToken() throws JwtSigningException
    {
        JwtWriter writer = new NimbusJwtWriter(SigningAlgorithm.HS256, new MACSigner(SHARED_SECRET));
        String json = "{\"iss\":\"joe\",\n"
                + " \"exp\":1300819380,\n"
                + " \"http://example.com/is_root\":true}";
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLAogImV4cCI6MTMwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.FiSys799P0mmChbQXoj76wsXrjnPP7HDlIW76orDjV8";
        assertThat(writer.jsonToJwt(json), is(jwt));
    }

    // compare written token to the tokens generated by our homegrown HmacJwtSigner
    @Test
    public void compareWrittenTokenToAltImplToken() throws JwtSigningException
    {
        JwtWriter writer = new NimbusJwtWriter(SigningAlgorithm.HS256, new MACSigner(SHARED_SECRET));
        String json = "{\"iss\":\"joe\",\n"
                + " \"exp\":1300819380,\n"
                + " \"http://example.com/is_root\":true}";
        String jwt = new HmacJwtSigner(SHARED_SECRET).jsonToHmacSha256Jwt(json);
        assertThat(writer.jsonToJwt(json), is(jwt));
    }

    // compare token that NimbusJwtWriter generates to token generated online at http://kjur.github.io/jsjws/tool_jwt.html
    @Test
    public void compareWrittenRs256TokenToTokenGeneratedOnline() throws Exception
    {
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(PRIVATE_KEY_FILE_NAME);
        RSAPrivateKey privateKey = KeyUtils.readRsaKeyFromPem(new InputStreamReader(in)).right().get();

        JwtWriter jwtWriter = new NimbusJwtWriter(SigningAlgorithm.RS256, new RSASSASigner(privateKey));
        String json = "{\"iss\":\"joe\",\n"
                + " \"sub\":\"bloggs\"}";

        String jwtGeneratedOnline = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJzdWIiOiJibG9nZ3MifQ.zAw073_t1VE2I44sHmSLL3UuLgwfMmm4tR0vGN5RuaJarPU84Ig3KPlqaD6dNx51xc0ZyEQSj_B0rn_gSukR1dmpPoNB_zu_77nGcIbpwwLapLsFy2utGAIVZnK5bZ2-MVPtVNruNyYUwLGKLDR4DGue1SgUc9nzaK099hcYwIo";

        assertThat(jwtWriter.jsonToJwt(json), is(jwtGeneratedOnline));
    }
}
