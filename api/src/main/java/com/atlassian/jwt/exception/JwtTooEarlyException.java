package com.atlassian.jwt.exception;

import java.util.Date;

public class JwtTooEarlyException extends JwtVerificationException
{
    public JwtTooEarlyException(Date notBefore, Date now)
    {
        super(String.format("Not-before time is %s and time is now %s", notBefore, now));
    }
}
