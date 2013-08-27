package com.atlassian.jwt.server.servlet;

import com.atlassian.jwt.server.SecretStore;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_OK;

/**
 *
 */
public class JwtRegistrationServlet extends HttpServlet
{
    public static final String PATH = "/register";

    private final SecretStore secretStore;

    public JwtRegistrationServlet(SecretStore secretStore)
    {
        this.secretStore = secretStore;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
    {
        String serverId = req.getParameter("myId");
        String clientId = req.getParameter("yourId");
        String secret = req.getParameter("secret");

        System.out.println("myId: " + serverId);
        System.out.println("yourId: " + clientId);
        System.out.println("secret: " + secret);

        if (StringUtils.isBlank(clientId) || StringUtils.isBlank(serverId) || StringUtils.isBlank(secret))
        {
            resp.sendError(SC_BAD_REQUEST, "myId, yourId and secret are required");
        }
        else
        {
            secretStore.update(clientId, serverId, secret);
            resp.setStatus(SC_OK);
            resp.getWriter().println("OK");
        }
    }
}
