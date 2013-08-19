package it;

import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.google.common.collect.ImmutableMap;
import it.rule.JwtPeerRegistration;
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
    private JwtPeer peer = new JwtPeer();

    @Rule
    public JwtPeerRegistration lifecycle = new JwtPeerRegistration(peer, this);

    @Test
    public void testRequestSignedWithJwtHs256() throws Exception
    {
        JSONObject json = new JSONObject(ImmutableMap.builder()
                .put("iat", TimeUtil.currentTimeSeconds())
                .put("exp", TimeUtil.currentTimePlusNSeconds(60))
                .build());
        HttpUtil.post(relayResource(peer.getSecretStore().getId()), ImmutableMap.of(
                "path", "verify",
                "method", "POST",
                "payload", json.toString()
        ), and(expectStatus(SC_OK), expectBody("OK")));
    }

}
