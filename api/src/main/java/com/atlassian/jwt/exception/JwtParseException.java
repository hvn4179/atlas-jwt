package com.atlassian.jwt.exception;

import java.text.ParseException;

public class JwtParseException extends Exception
{
    public JwtParseException(ParseException cause)
    {
        super(cause);
    }

    public JwtParseException(String reason)
    {
        super(reason);
    }
}
