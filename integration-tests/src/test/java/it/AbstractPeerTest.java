package it;

import com.atlassian.jira.pageobjects.JiraTestedProduct;
import com.atlassian.jwt.server.JwtPeer;
import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import com.atlassian.jwt.util.HttpUtil;
import com.atlassian.pageobjects.Defaults;
import com.atlassian.pageobjects.TestedProduct;
import com.google.common.collect.ImmutableMap;
import it.util.TestedProductHolder;

import java.io.IOException;

import static it.util.HttpResponseConsumers.expectStatus;
import static javax.servlet.http.HttpServletResponse.SC_NO_CONTENT;
import static javax.servlet.http.HttpServletResponse.SC_OK;

/**
 *
 */
public abstract class AbstractPeerTest
{
    protected final String baseUrl;
    private final String contextPath;

    public AbstractPeerTest()
    {
        this(JiraTestedProduct.class);
    }

    public AbstractPeerTest(Class<? extends TestedProduct> testedProductClass)
    {
        if (System.getProperty("baseurl") == null)
        {
            Defaults defs = testedProductClass.getAnnotation(Defaults.class);
            contextPath = defs.contextPath();
            baseUrl = "http://localhost:" + defs.httpPort() + contextPath;
        }
        else
        {
            contextPath = TestedProductHolder.INSTANCE.getProductInstance().getContextPath();
            baseUrl = TestedProductHolder.INSTANCE.getProductInstance().getBaseUrl();
        }
    }

    protected String getContextPath()
    {
        return contextPath;
    }

    protected String jwtTestBasePath()
    {
        return baseUrl + "/rest/jwt-test/latest";
    }

    protected String registrationResource()
    {
        return jwtTestBasePath() + "/register";
    }

    protected String whoAmIResource()
    {
        return jwtTestBasePath() + "/whoami";
    }

    protected String relayResource(String id)
    {
        return jwtTestBasePath() + "/relay/" + id;
    }

    public void registerPeer(JwtPeer peer) throws IOException
    {
        HttpUtil.post(registrationResource(), ImmutableMap.of(
                "baseUrl", peer.getBaseUrl(),
                "path", JwtRegistrationServlet.PATH
        ), expectStatus(SC_OK));
    }

    public void unregisterPeer(JwtPeer peer) throws IOException
    {
        HttpUtil.delete(registrationResource() + "/" + peer.getSecretStore().getClientId(), expectStatus(SC_NO_CONTENT));
    }

}
