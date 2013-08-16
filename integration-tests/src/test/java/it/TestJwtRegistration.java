package it;

import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import com.google.common.collect.ImmutableMap;
import it.util.HttpUtil;
import org.apache.http.HttpResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;

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
        HttpResponse resp = HttpUtil.post(baseUrl + "/rest/jwt-test/latest/register", ImmutableMap.of(
            "baseUrl", peer.getBaseUrl(),
            "path", JwtRegistrationServlet.PATH
        ));
        assertEquals(200, resp.getStatusLine().getStatusCode());
    }

}
