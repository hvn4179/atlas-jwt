package it;

import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import com.google.common.collect.ImmutableMap;
import com.atlassian.jwt.util.HttpUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static it.util.HttpResponseConsumers.expectStatus;
import static javax.servlet.http.HttpServletResponse.SC_NO_CONTENT;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;

/**
 *
 */
public class TestJwtRegistration extends AbstractBrowserlessTest
{
    private JwtPeer peer;

    @Before
    public void setUp() throws Exception {
        peer = new JwtPeer();
        peer.start();
    }

    @After
    public void tearDown() throws Exception {

        peer.stop();
    }

    @Test
    public void testRegistration() throws Exception {
        HttpUtil.post(registrationResource(), ImmutableMap.of(
            "baseUrl", peer.getBaseUrl(),
            "path", JwtRegistrationServlet.PATH
        ), expectStatus(SC_OK));

        String id = peer.getSecretStore().getId();
        assertNotNull(id);
        assertTrue(id.length() > 0);

        String secret = peer.getSecretStore().getSecret();
        assertNotNull(secret);
        // shared secret for HMAC SHA-256 should be at least 256 bits long
        // this is just a smoke test, it doesn't verify key strength
        assertTrue(secret.getBytes().length >= 32);

        HttpUtil.delete(registrationResource() + "/" + id, expectStatus(SC_NO_CONTENT));
    }

}
