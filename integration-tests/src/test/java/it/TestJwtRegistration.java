package it;

import com.atlassian.jwt.server.JwtPeer;
import it.rule.JwtPeerLifecycle;
import org.junit.Rule;
import org.junit.Test;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;

/**
 * Tests that an Atlassian app can issue JWT credentials to a third party.
 * <p/>
 * Note that if this test fails, the rest probably will too.
 */
public class TestJwtRegistration extends AbstractPeerTest
{
    private JwtPeer peer = new JwtPeer();

    @Rule
    public JwtPeerLifecycle peerRule = new JwtPeerLifecycle(peer);

    @Test
    public void testRegistration() throws Exception
    {
        registerPeer(peer);

        String id = peer.getSecretStore().getId();
        assertNotNull(id);
        assertTrue(id.length() > 0);

        String secret = peer.getSecretStore().getSecret();
        assertNotNull(secret);
        // shared secret for HMAC SHA-256 should be at least 256 bits long
        // this is just a smoke test, it doesn't verify key strength
        assertTrue(secret.getBytes().length >= 32);

        unregisterPeer(peer);
    }

}
