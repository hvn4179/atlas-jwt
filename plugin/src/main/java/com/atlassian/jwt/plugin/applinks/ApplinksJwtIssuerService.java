package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.core.reader.JwtIssuerSharedSecretService;
import com.atlassian.jwt.core.reader.JwtIssuerValidator;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;

import static com.atlassian.jwt.JwtConstants.AppLinks.SHARED_SECRET_PROPERTY_NAME;

public class ApplinksJwtIssuerService implements JwtIssuerValidator, JwtIssuerSharedSecretService
{
    private final JwtApplinkFinder jwtApplinkFinder;

    public ApplinksJwtIssuerService(JwtApplinkFinder jwtApplinkFinder)
    {
        this.jwtApplinkFinder = jwtApplinkFinder;
    }

    @Override
    public boolean isValid(String issuer)
    {
        return null != issuer && null != jwtApplinkFinder.find(issuer);
    }

    @Override
    public String getSharedSecret(String issuer) throws JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException
    {
        ApplicationLink applicationLink = null == issuer ? null : jwtApplinkFinder.find(issuer);

        if (null == applicationLink)
        {
            throw new JwtUnknownIssuerException(String.format("Issuer '%s' does not have an application link", issuer));
        }

        String secret = (String) applicationLink.getProperty(SHARED_SECRET_PROPERTY_NAME);

        if (null == secret)
        {
            throw new JwtIssuerLacksSharedSecretException(issuer);
        }

        return secret;
    }
}
