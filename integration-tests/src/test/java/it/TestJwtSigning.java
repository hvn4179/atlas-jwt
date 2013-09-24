package it;

import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.HttpRequestCanonicalizer;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.httpclient.CanonicalHttpUriRequest;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.google.common.collect.ImmutableMap;
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
    @SuppressWarnings("unchecked")
    public void testRequestSignedWithJwtHs256() throws Exception
    {
        String targetUri = "/verify";
        String querySignature = JwtUtil.computeSha256Hash(HttpRequestCanonicalizer.canonicalize(new CanonicalHttpUriRequest(new HttpPost(targetUri), "")));
        String clientId = peer.getSecretStore().getClientId();
        JSONObject json = new JSONObject(ImmutableMap.builder()
                .put("iat", TimeUtil.currentTimeSeconds())
                .put("exp", TimeUtil.currentTimePlusNSeconds(60))
                .put("iss", clientId)
                .put(JwtConstants.Claims.QUERY_HASH, querySignature)
                .build());
        HttpUtil.post(relayResource(clientId), ImmutableMap.of(
                "path", targetUri,
                "method", "POST",
                "payload", json.toString()
        ), and(expectStatus(SC_OK), expectBody("OK")));
    }

}
