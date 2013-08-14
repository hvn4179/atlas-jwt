package com.atlassian.jwt.exception;

public class JwtSignatureMismatchException extends Exception
{
    public JwtSignatureMismatchException(Exception cause)
    {
        super(cause);
    }

    public JwtSignatureMismatchException(String reason)
    {
        super(reason);
    }
}
