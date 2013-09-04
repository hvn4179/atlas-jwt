package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationId;
import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.core.reader.JwtIssuerSharedSecretService;
import com.atlassian.jwt.core.reader.JwtIssuerValidator;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.atlassian.jwt.plugin.applinks.ApplinksJwtPeerService.ATLASSIAN_JWT_SHARED_SECRET;

public class ApplinksJwtIssuerService implements JwtIssuerValidator, JwtIssuerSharedSecretService
{
    private static final Logger log = LoggerFactory.getLogger(ApplinksJwtIssuerService.class);

    private final ApplicationLinkService applicationLinkService;

    public ApplinksJwtIssuerService(ApplicationLinkService applicationLinkService)
    {
        this.applicationLinkService = applicationLinkService;
    }

    @Override
    public boolean isValid(String issuer)
    {
        return null != getApplicationLink(issuer);
    }

    @Override
    public String getSharedSecret(String issuer) throws JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
    {
        ApplicationLink applicationLink = getApplicationLink(issuer);

        if (null == applicationLink)
        {
            throw new JwtUnknownIssuerException(String.format("Issuer '%s' does not have an application link", issuer));
        }

        String secret = (String) applicationLink.getProperty(ATLASSIAN_JWT_SHARED_SECRET);

        if (null == secret)
        {
            throw new JwtIssuerLacksSharedSecretException(issuer);
        }

        return secret;
    }

    private ApplicationLink getApplicationLink(String issuer)
    {
        ApplicationLink applicationLink = null;

        try
        {
            applicationLink = applicationLinkService.getApplicationLink(new ApplicationId(issuer));
        }
        catch (TypeNotInstalledException e)
        {
            log.warn("Encountered exception while finding application link for JWT issuer '{}'", issuer, e);
            throw new IllegalArgumentException(e);
        }

        return applicationLink;
    }
}
