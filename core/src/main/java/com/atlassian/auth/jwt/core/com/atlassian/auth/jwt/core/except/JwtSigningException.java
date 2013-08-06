package com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except;

/**
 * Author: pbrownlow
 * Date: 31/07/13
 * Time: 12:28 PM
 */
public class JwtSigningException extends Throwable
{
    public JwtSigningException(Exception cause)
    {
        super(cause);
    }
}
