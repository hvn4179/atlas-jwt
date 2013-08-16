package it.rule;

import com.atlassian.jwt.server.JwtPeer;
import it.AbstractPeerTest;
import org.junit.rules.ExternalResource;

/**
 *
 */
public class JwtPeerRegistration extends JwtPeerLifecycle
{
    private final AbstractPeerTest test;

    public JwtPeerRegistration(JwtPeer peer, AbstractPeerTest test)
    {
        super(peer);
        this.test = test;
    }

    @Override
    protected void before() throws Throwable
    {
        super.before();
        test.registerPeer(peer);
    }

    @Override
    protected void after()
    {
        try {
            test.unregisterPeer(peer);
        } catch (Exception e) {
            // oh well. let the original test failure bubble up
        }
        super.after();
    }

}
