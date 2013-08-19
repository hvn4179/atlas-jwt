package it.rule;

import com.atlassian.jwt.server.JwtPeer;
import org.junit.rules.ExternalResource;

/**
 *
 */
public class JwtPeerLifecycle extends ExternalResource
{
    protected final JwtPeer peer;

    public JwtPeerLifecycle(JwtPeer peer)
    {
        this.peer = peer;
    }

    @Override
    protected void before() throws Throwable
    {
        peer.start();
    }

    @Override
    protected void after()
    {
        try
        {
            peer.stop();
        }
        catch (Exception e)
        {
            // oh well. let the original test failure bubble up
        }
    }

}
