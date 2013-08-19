package it;

import com.atlassian.jwt.core.writer.NimbusJwtWriterFactory;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.jwt.util.TimeUtil;
import com.atlassian.jwt.writer.JwtWriter;
import com.google.common.collect.ImmutableMap;
import it.rule.JwtPeerRegistration;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;

import static com.atlassian.jwt.SigningAlgorithm.HS256;
import static it.util.HttpResponseConsumers.expectBody;

/**
 * Tests that an Atlassian app can authenticate incoming requests by their JWTs.
 */
public class TestJwtAuthentication extends AbstractPeerTest
{
    private JwtPeer peer = new JwtPeer();

    @Rule
    public JwtPeerRegistration lifecycle = new JwtPeerRegistration(peer, this);

    @Test
    public void testRequestSignedWithJwtHs256() throws Exception
    {
        JwtWriter jwtWriter = new NimbusJwtWriterFactory().forSharedSecret(HS256, peer.getSecretStore().getSecret());
        JSONObject json = new JSONObject(ImmutableMap.builder()
            .put("iss", peer.getSecretStore().getId())
            .put("prn", "admin")
            .put("alg", HS256.name())
            .put("typ", "JWT")
            .put("iat", TimeUtil.currentTimeSeconds())
            .put("exp", TimeUtil.currentTimePlusNSeconds(60))
        .build());
        String jwt = jwtWriter.jsonToJwt(json.toString());
        HttpUtil.get(whoAmIResource(), expectBody("anonymous")); // sanity check
        testWhoAmIWithJwtInHeaderAndQueryString(jwt);
    }

    private void testWhoAmIWithJwtInHeaderAndQueryString(String jwt) throws Exception
    {
        HttpUtil.get(whoAmIResource() + "?jwt=" + jwt, expectBody("admin"));
        HttpUtil.get(whoAmIResource(), ImmutableMap.of("Authorization", "JWT " + jwt), expectBody("admin"));
    }

}
