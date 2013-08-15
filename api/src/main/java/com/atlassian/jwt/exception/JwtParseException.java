package com.atlassian.jwt.exception;

import java.text.ParseException;

/**
 * Indicates that the JWT was not well-formed. For example: the JWT is not valid JSON, an expected claim is missing, or
 * the value of a reserved claim did not match its expected format.
 *
 * @since 1.0
 */
public class JwtParseException extends Exception
{
    public JwtParseException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public JwtParseException(ParseException cause)
    {
        super(cause);
    }

    public JwtParseException(String reason)
    {
        super(reason);
    }
}
