package it;

import com.atlassian.jwt.server.JwtPeer;
import it.rule.JwtPeerRegistration;
import org.junit.*;

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

    }

}
