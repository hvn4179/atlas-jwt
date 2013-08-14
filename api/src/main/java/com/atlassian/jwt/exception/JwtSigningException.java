package com.atlassian.jwt.exception;

public class JwtSigningException extends Throwable
{
    public JwtSigningException(Exception cause)
    {
        super(cause);
    }
}
