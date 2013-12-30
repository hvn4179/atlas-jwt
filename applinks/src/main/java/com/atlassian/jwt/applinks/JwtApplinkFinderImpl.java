package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;

public class JwtApplinkFinderImpl implements JwtApplinkFinder
{
    private final ApplicationLinkService applicationLinkService;

    public JwtApplinkFinderImpl(ApplicationLinkService applicationLinkService)
    {
        this.applicationLinkService = applicationLinkService;
    }

    @Override
    public ApplicationLink find(String addOnId)
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
