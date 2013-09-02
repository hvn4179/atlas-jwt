package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationId;
import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.core.reader.JwtIssuerSharedSecretService;
import com.atlassian.jwt.core.reader.JwtIssuerValidator;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;

import static com.atlassian.jwt.plugin.applinks.ApplinksJwtPeerService.ATLASSIAN_JWT_SHARED_SECRET;

public class ApplinksJwtIssuerService implements JwtIssuerValidator, JwtIssuerSharedSecretService
{
    private final ApplicationLinkService applicationLinkService;

    public ApplinksJwtIssuerService(ApplicationLinkService applicationLinkService)
    {
        this.applicationLinkService = applicationLinkService;
    }

    @Override
    public boolean isValid(String issuer)
    {
        try
        {
            return null != applicationLinkService.getApplicationLink(new ApplicationId(issuer));
        }
        catch (TypeNotInstalledException e)
        {
            return false;
        }
    }

    @Override
    public String getSharedSecret(String issuer) throws JwtIssuerLacksSharedSecretException
    {
        ApplicationLink applicationLink = null;

        try
        {
            applicationLink = applicationLinkService.getApplicationLink(new ApplicationId(issuer));
        }
        catch (TypeNotInstalledException e)
        {
            throw new IllegalArgumentException(e);
        }

        if (null == applicationLink)
        {
            throw new IllegalArgumentException(String.format("Issuer does not have an application link: '%s'", issuer));
        }

        String secret = (String) applicationLink.getProperty(ATLASSIAN_JWT_SHARED_SECRET);

        if (null == secret)
        {
            throw new JwtIssuerLacksSharedSecretException(issuer);
        }

        return secret;
    }
}
