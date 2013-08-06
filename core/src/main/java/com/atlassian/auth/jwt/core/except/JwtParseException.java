package com.atlassian.auth.jwt.core.except;

import java.text.ParseException;

/**
 * Author: pbrownlow
 * Date: 30/07/13
 * Time: 5:42 PM
 */
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
