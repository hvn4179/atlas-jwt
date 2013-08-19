package com.atlassian.jwt.applinks.exception;

import com.atlassian.applinks.api.ApplicationLink;

/**
 * Thrown if issuing credentials to a {@link ApplicationLink linked application} failed.
 *
 * @since 1.0
 */
public class JwtRegistrationFailed extends Exception
{
    public JwtRegistrationFailed(String message)
    {
        super(message);
    }

    public JwtRegistrationFailed(String message, Throwable cause)
    {
        super(message, cause);
    }

    public JwtRegistrationFailed(Throwable cause)
    {
        super(cause);
    }

}
