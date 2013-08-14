package com.atlassian.jwt.exception;

import java.util.Date;

public class ExpiredJwtException extends Exception
{
    public ExpiredJwtException(Date expiredAt, Date now)
    {
        super(String.format("Expired at %s and time is now %s", expiredAt, now));
    }
}
