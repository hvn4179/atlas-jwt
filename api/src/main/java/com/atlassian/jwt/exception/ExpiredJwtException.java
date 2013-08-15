package com.atlassian.jwt.exception;

import java.util.Date;

/**
 * Thrown if the JWT's timestamps show that it has expired.
 *
 * @since 1.0
 */
public class ExpiredJwtException extends JwtVerificationException
{
    public ExpiredJwtException(Date expiredAt, Date now)
    {
        super(String.format("Expired at %s and time is now %s", expiredAt, now));
    }
}
