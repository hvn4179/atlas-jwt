package com.atlassian.jwt.server.servlet;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.core.reader.NimbusJwtReaderFactory;
import com.atlassian.jwt.httpclient.CanonicalHttpServletRequest;
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
        TrivialJwtPeerSharedSecretService jwtPeerSharedSecretService = new TrivialJwtPeerSharedSecretService(secretStore);
        readerFactory = new NimbusJwtReaderFactory(jwtPeerSharedSecretService, jwtPeerSharedSecretService);
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

        Jwt jwt;
        try
        {
            JwtReader reader = readerFactory.getReader(jwtString);
            jwt = reader.read(jwtString, JwtClaimVerifiersBuilder.build(new CanonicalHttpServletRequest(req), reader));
        }
        catch (Exception e)
        {
            handleJwtException(resp, e);
            return;
        }

        requestCache.setMostRecentPayload(jwt.getJsonPayload());

        resp.setStatus(SC_OK);
        resp.getWriter().write(jwt.getJsonPayload());
    }

    private void handleJwtException(HttpServletResponse resp, Exception e) throws IOException
    {
        String message = "Failed to verify JWT.";
        resp.sendError(SC_BAD_REQUEST, message);
        log.error(message, e);
    }
}
