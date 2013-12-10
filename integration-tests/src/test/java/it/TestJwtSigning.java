package it;

import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.core.writer.JsonSmartJwtJsonBuilder;
import com.atlassian.jwt.core.writer.JwtClaimsBuilder;
import com.atlassian.jwt.httpclient.CanonicalHttpUriRequest;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import com.google.common.collect.ImmutableMap;
import it.rule.JwtPeerRegistration;
import org.apache.http.client.methods.HttpPost;
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
        String clientId = peer.getSecretStore().getClientId();
        JwtJsonBuilder jsonBuilder = new JsonSmartJwtJsonBuilder()
                .issuedAt(TimeUtil.currentTimeSeconds())
                .expirationTime(TimeUtil.currentTimePlusNSeconds(60))
                .issuer(clientId);
        JwtClaimsBuilder.appendHttpRequestClaims(jsonBuilder, new CanonicalHttpUriRequest("POST", targetUri, getContextPath()));
        HttpUtil.post(relayResource(clientId), ImmutableMap.of(
                "path", targetUri,
                "method", "POST",
                "payload", jsonBuilder.build()
        ), and(expectStatus(SC_OK), expectBody("OK")));
    }

}
