package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationId;
import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.applinks.exception.NotAJwtPeerException;
import com.atlassian.jwt.core.reader.JwtClaimVerificationsBuilder;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;

import java.util.Map;

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
    public ApplinkJwt verifyJwt(String jwt, Map<String, String> signedClaimSigningInputs) throws NotAJwtPeerException, JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
    {
        JwtReader reader = jwtReaderFactory.getReader(jwt);
        Jwt verifiedJwt = reader.read(jwt, JwtClaimVerificationsBuilder.buildNameToVerifierMap(signedClaimSigningInputs, reader));
        ApplicationLink applicationLink = getApplicationLink(verifiedJwt);
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

    @Override
    public ApplicationLink getApplicationLink(Jwt jwt) throws TypeNotInstalledException
    {
        String applicationId = jwt.getIssuer();
        return applicationLinkService.getApplicationLink(new ApplicationId(applicationId));
    }

}
