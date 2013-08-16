package it;

import com.atlassian.jwt.server.JwtPeer;
import it.rule.JwtPeerRegistration;
import org.junit.Rule;

/**
 * Tests that an Atlassian app can authenticate incoming requests by their JWTs.
 */
public class TestJwtAuthentication extends AbstractPeerTest
{
    private JwtPeer peer = new JwtPeer();

    @Rule
    public JwtPeerRegistration lifecycle = new JwtPeerRegistration(peer, this);


}
