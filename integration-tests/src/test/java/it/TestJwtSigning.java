package it;

import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.core.writer.NimbusJwtWriter;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.jwt.writer.JwtWriter;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.crypto.MACSigner;
import it.rule.JwtPeerRegistration;
import org.apache.http.client.methods.HttpPost;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;

import static it.util.HttpResponseConsumers.*;
import static javax.servlet.http.HttpServletResponse.SC_OK;

/**
 * Tests that the Atlassian app can make requests to a third party app that consumes JWTs.
 */
public class TestJwtSigning extends AbstractPeerTest
{
    private final JwtPeer peer = new JwtPeer();

    @Rule
    public JwtPeerRegistration lifecycle = new JwtPeerRegistration(peer, this);

    @Test
    public void testRequestSignedWithJwtHs256() throws Exception
    {
        JwtWriter jwtWriter = new NimbusJwtWriter(SigningAlgorithm.HS256, new MACSigner(peer.getSecretStore().getSecret()));
        String targetUri = "/verify";
        String querySignature = jwtWriter.sign(JwtUtil.canonicalizeQuery(new HttpPost(targetUri)));
        String clientId = peer.getSecretStore().getClientId();
        JSONObject json = new JSONObject(ImmutableMap.builder()
                .put("iat", TimeUtil.currentTimeSeconds())
                .put("exp", TimeUtil.currentTimePlusNSeconds(60))
                .put("iss", clientId)
                .put(JwtConstants.Claims.QUERY_SIGNATURE, querySignature)
                .build());
        HttpUtil.post(relayResource(clientId), ImmutableMap.of(
                "path", targetUri,
                "method", "POST",
                "payload", json.toString()
        ), and(expectStatus(SC_OK), expectBody("OK")));
    }

}
