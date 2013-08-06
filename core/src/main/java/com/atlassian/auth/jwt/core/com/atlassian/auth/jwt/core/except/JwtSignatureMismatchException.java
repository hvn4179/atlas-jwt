package com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except;

/**
 * Author: pbrownlow
 * Date: 30/07/13
 * Time: 5:41 PM
 */
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
