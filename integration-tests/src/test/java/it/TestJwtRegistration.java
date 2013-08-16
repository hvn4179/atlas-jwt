package it;

import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import com.google.common.collect.Lists;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.apache.http.NameValuePair;

import java.util.List;

import static junit.framework.Assert.assertEquals;

/**
 *
 */
public class TestJwtRegistration extends AbstractBrowserlessTest
{
    private final DefaultHttpClient httpClient = new DefaultHttpClient();

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
        HttpPost post = new HttpPost(baseUrl + "/rest/jwt-test/latest/register");
        List<NameValuePair> params = Lists.newArrayList();
        params.add(new BasicNameValuePair("baseUrl", peer.getBaseUrl()));
        params.add(new BasicNameValuePair("path", JwtRegistrationServlet.PATH));
        post.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse resp = httpClient.execute(post);
        assertEquals(200, resp.getStatusLine().getStatusCode());
    }

}
