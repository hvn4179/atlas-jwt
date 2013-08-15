package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;

/**
 * Indicates that this server does not have a JWT relationship (e.g. shared secrets) with the specified
 * {@link ApplicationLink}.
 */
public class NotAJwtPeerException extends RuntimeException
{
    public NotAJwtPeerException(ApplicationLink applicationLink)
    {
        super(applicationLink + " is not a valid JWT peer.");
    }
}
