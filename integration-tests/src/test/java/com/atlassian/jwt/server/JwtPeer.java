package com.atlassian.jwt.server;

import com.atlassian.jwt.server.servlet.JwtRegistrationServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class JwtPeer
{

    private Server server;
    private int port;
    private SecretStore secretStore;

    public void start() throws Exception
    {
        port = ServerUtils.pickFreePort();
        server = new Server(port);
        secretStore = new SecretStore();

        HandlerList list = new HandlerList();
        server.setHandler(list);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        context.addServlet(new ServletHolder(new JwtRegistrationServlet(secretStore)), JwtRegistrationServlet.PATH);

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

    public String getBaseUrl()
    {
        return "http://localhost:" + port;
    }
}
