package com.atlassian.jwt.server;

import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import com.atlassian.jwt.server.servlet.JwtVerificationServlet;
import com.atlassian.jwt.util.ServerUtil;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * A lightweight Jetty app for testing an Atlassian product's JWT capabilities.
 */
public class JwtPeer
{

    private Server server;
    private int port;

    private SecretStore secretStore;
    private RequestCache requestCache;

    public void start() throws Exception
    {
        port = ServerUtil.pickFreePort();
        server = new Server(port);
        secretStore = new SecretStore();
        requestCache = new RequestCache();

        HandlerList list = new HandlerList();
        server.setHandler(list);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        context.addServlet(new ServletHolder(new JwtRegistrationServlet(secretStore)), JwtRegistrationServlet.PATH);
        context.addServlet(new ServletHolder(new JwtVerificationServlet(secretStore, requestCache)), JwtVerificationServlet.PATH);

        list.addHandler(context);
        server.start();
    }

    public void stop() throws Exception
    {
        if (server != null)
        {
            server.stop();
        }
    }

    public SecretStore getSecretStore()
    {
        return secretStore;
    }

    public RequestCache getRequestCache()
    {
        return requestCache;
    }

    public String getBaseUrl()
    {
        return "http://localhost:" + port;
    }
}
