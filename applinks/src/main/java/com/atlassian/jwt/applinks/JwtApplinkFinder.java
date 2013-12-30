package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;

public class JwtApplinkFinder
{
    /**
     * Find an {@link ApplicationLink} with the given add-on id that uses JWT authentication.
     * @param applicationLinkService {@link ApplicationLinkService} that will supply the {@link ApplicationLink}s
     * @param addOnId AKA the "plugin key"
     * @return the first matching {@link ApplicationLink} or null if there are no matches
     * @throws IllegalArgumentException if the id argument is null
     */
    public static ApplicationLink find(ApplicationLinkService applicationLinkService, String addOnId)
    {
        if (null == addOnId)
        {
            throw new IllegalArgumentException("Add-on id cannot be null");
        }

        for (ApplicationLink appLink : applicationLinkService.getApplicationLinks())
        {
            if (addOnId.equals(appLink.getProperty(JwtApplinkConstants.PLUGIN_KEY_PROPERTY)) &&
                JwtApplinkConstants.JWT_AUTH_METHOD.equals(appLink.getProperty(JwtApplinkConstants.AUTH_METHOD_PROPERTY)))
            {
                return appLink;
            }
        }

        return null;
    }
}
