package it;

import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.jwt.util.TimeUtil;
import com.google.common.collect.ImmutableMap;
import it.rule.JwtPeerRegistration;
import it.util.HttpResponseConsumers;
import org.json.JSONObject;
import org.junit.*;

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
        String payLoad = new JSONObject(ImmutableMap.of(
            "testKey", "testValue",
            "exp", TimeUtil.currentTimePlusNSeconds(60)
        )).toString();
        HttpUtil.post(relayResource(peer.getSecretStore().getId()), ImmutableMap.of(
            "path", "verify",
            "method", "POST",
            "payload", payLoad
        ), HttpResponseConsumers.expectStatus(SC_OK));
    }

}
