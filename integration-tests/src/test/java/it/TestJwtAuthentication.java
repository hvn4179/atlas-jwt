package it;

import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.CanonicalHttpRequests;
import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.core.writer.JsonSmartJwtJsonBuilder;
import com.atlassian.jwt.core.writer.NimbusJwtWriter;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import com.atlassian.jwt.writer.JwtWriter;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.crypto.MACSigner;
import it.rule.JwtPeerRegistration;
import org.apache.http.client.methods.HttpGet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;

import static it.util.HttpResponseConsumers.expectBody;

/**
 * Tests that an Atlassian app can authenticate incoming requests by their JWTs.
 */
public class TestJwtAuthentication extends AbstractPeerTest
{
    private final JwtPeer peer = new JwtPeer();

    @Rule
    public final JwtPeerRegistration lifecycle = new JwtPeerRegistration(peer, this);
    private JwtWriter jwtWriter;

    @Before
    public void before()
    {
        jwtWriter = new NimbusJwtWriter(SigningAlgorithm.HS256, new MACSigner(peer.getSecretStore().getSecret()));
    }

    @Test
    public void testRequestFromAnonymous() throws IOException
    {
        HttpUtil.get(whoAmIResource(), expectBody("anonymous")); // sanity check
    }

    @Test
    public void testRequestSignedWithJwtHs256InQueryString() throws Exception
    {
        String jwt = jwtWriter.jsonToJwt(createJwtJsonBuilder(whoAmIResource()).build());
        HttpUtil.get(whoAmIResource() + "?jwt=" + jwt, expectBody("admin"));
    }

    @Test
    public void testRequestSignedWithJwtHs256InHeader() throws Exception
    {
        String jwt = jwtWriter.jsonToJwt(createJwtJsonBuilder(whoAmIResource()).build());
        HttpUtil.get(whoAmIResource(), ImmutableMap.of("Authorization", "JWT " + jwt), expectBody("admin"));
    }

    private JwtJsonBuilder createJwtJsonBuilder(String url) throws IOException
    {
        return new JsonSmartJwtJsonBuilder()
                    .issuer(peer.getSecretStore().getClientId())
                    .subject("admin")
                    .issuedAt(TimeUtil.currentTimeSeconds())
                    .expirationTime(TimeUtil.currentTimePlusNSeconds(60))
                    .claim(JwtConstants.Claims.QUERY_SIGNATURE, jwtWriter.sign(CanonicalHttpRequests.from(new HttpGet(url), getContextPath()).canonicalize()));
    }
}
