package com.atlassian.jwt.applinks;

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
