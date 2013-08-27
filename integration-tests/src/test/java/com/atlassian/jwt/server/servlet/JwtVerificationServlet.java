package com.atlassian.jwt.server.servlet;

import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.reader.NimbusJwtReaderFactory;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.server.RequestCache;
import com.atlassian.jwt.server.SecretStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class JwtVerificationServlet extends HttpServlet
{
    public static final String PATH = "/verify";

    private static final Logger log = LoggerFactory.getLogger(JwtVerificationServlet.class);

    private final JwtReaderFactory readerFactory;
    private final SecretStore secretStore;
    private final RequestCache requestCache;

    public JwtVerificationServlet(SecretStore secretStore, RequestCache requestCache)
    {
        this.secretStore = secretStore;
        this.requestCache = requestCache;
        readerFactory = new NimbusJwtReaderFactory();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
    {
        String jwtString = JwtUtil.extractJwt(req);
        if (jwtString == null)
        {
            resp.sendError(SC_BAD_REQUEST, "No JWT found in request.");
            return;
        }

        if (secretStore.getSecret() == null)
        {
            throw new IllegalStateException("Shared secret not initialized!");
        }

        JwtReader reader = readerFactory.macVerifyingReader(secretStore.getSecret());

        VerifiedJwt jwt;
        try
        {
            jwt = reader.verify(jwtString);
        }
        catch (Exception e)
        {
            String message = "Failed to verify JWT.";
            resp.sendError(SC_BAD_REQUEST, message);
            log.error(message, e);
            return;
        }

        requestCache.setMostRecentPayload(jwt.getJsonPayload());

        resp.setStatus(SC_OK);
        resp.getWriter().write(jwt.getJsonPayload());
    }
}
