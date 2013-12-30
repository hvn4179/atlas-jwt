package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.applinks.exception.NotAJwtPeerException;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;

import java.util.Map;

import static com.atlassian.jwt.plugin.applinks.ApplinksJwtPeerService.ATLASSIAN_JWT_SHARED_SECRET;

public class ApplinksJwtService implements JwtService
{
    private final JwtReaderFactory jwtReaderFactory;
    private final JwtWriterFactory jwtWriterFactory;
    private final JwtApplinkFinder jwtApplinkFinder;

    public ApplinksJwtService(JwtReaderFactory jwtReaderFactory, JwtWriterFactory jwtWriterFactory,
                              JwtApplinkFinder jwtApplinkFinder)
    {
        this.jwtReaderFactory = jwtReaderFactory;
        this.jwtWriterFactory = jwtWriterFactory;
        this.jwtApplinkFinder = jwtApplinkFinder;
    }

    @Override
    public boolean isJwtPeer(ApplicationLink applicationLink)
    {
        return applicationLink.getProperty(ATLASSIAN_JWT_SHARED_SECRET) != null;
    }

    @Override
    public ApplinkJwt verifyJwt(String jwt, Map<String, ? extends JwtClaimVerifier> claimVerifiers) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
    {
        Jwt verifiedJwt = jwtReaderFactory.getReader(jwt).read(jwt, claimVerifiers);
        ApplicationLink applicationLink = jwtApplinkFinder.find(verifiedJwt.getIssuer());
        return new SimpleApplinkJwt(verifiedJwt, applicationLink);
    }

    private String requireSharedSecret(ApplicationLink applicationLink)
    {
        String sharedSecret = (String) applicationLink.getProperty(ATLASSIAN_JWT_SHARED_SECRET);
        if (sharedSecret == null)
        {
            throw new NotAJwtPeerException(applicationLink);
        }
        return sharedSecret;
    }

    @Override
    public String issueJwt(String jsonPayload, ApplicationLink applicationLink) throws NotAJwtPeerException, JwtSigningException
    {
        return getJwtWriter(applicationLink).jsonToJwt(jsonPayload);
    }

    private JwtWriter getJwtWriter(ApplicationLink applicationLink)
    {
        return jwtWriterFactory
                .macSigningWriter(SigningAlgorithm.HS256, requireSharedSecret(applicationLink));
    }
}
