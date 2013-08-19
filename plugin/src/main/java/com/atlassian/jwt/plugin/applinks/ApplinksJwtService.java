package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationId;
import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.applinks.NotAJwtPeerException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtSigningException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.writer.JwtWriterFactory;

import static com.atlassian.jwt.plugin.applinks.ApplinksJwtPeerService.ATLASSIAN_JWT_SHARED_SECRET;

public class ApplinksJwtService implements JwtService
{
    private final JwtReaderFactory jwtReaderFactory;
    private final JwtWriterFactory jwtWriterFactory;
    private final ApplicationLinkService applicationLinkService;

    public ApplinksJwtService(JwtReaderFactory jwtReaderFactory, JwtWriterFactory jwtWriterFactory,
                              ApplicationLinkService applicationLinkService)
    {
        this.jwtReaderFactory = jwtReaderFactory;
        this.jwtWriterFactory = jwtWriterFactory;
        this.applicationLinkService = applicationLinkService;
    }

    @Override
    public boolean isJwtPeer(ApplicationLink applicationLink)
    {
        return applicationLink.getProperty(ATLASSIAN_JWT_SHARED_SECRET) != null;
    }

    @Override
    public ApplinkJwt verifyJwt(String jwt) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException
    {
        UnverifiedJwt unverifiedJwt = jwtReaderFactory.unverified().parse(jwt);
        String applicationId = unverifiedJwt.getIssuer();
        ApplicationLink applicationLink = applicationLinkService.getApplicationLink(new ApplicationId(applicationId));
        JwtReader jwtReader = jwtReaderFactory.macVerifyingReader(requireSharedSecret(applicationLink));
        return new SimpleApplinkJwt(jwtReader.verify(jwt), applicationLink);
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
        return jwtWriterFactory
                .macSigningWriter(SigningAlgorithm.HS256, requireSharedSecret(applicationLink))
                .jsonToJwt(jsonPayload);
    }

}
