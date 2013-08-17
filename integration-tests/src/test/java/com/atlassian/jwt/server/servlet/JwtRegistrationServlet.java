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
        String id = req.getParameter("id");
        String secret = req.getParameter("secret");

        System.out.println("id: " + id);
        System.out.println("secret: " + secret);

        if (StringUtils.isBlank(id) || StringUtils.isBlank(secret)) {
            resp.sendError(SC_BAD_REQUEST, "id and secret are required");
        } else {
            secretStore.update(id, secret);
            resp.setStatus(SC_OK);
            resp.getWriter().println("OK");
        }
    }
}
