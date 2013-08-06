package com.atlassian.auth.jwt.core.except;

import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 30/07/13
 * Time: 5:37 PM
 */
public class ExpiredJwtException extends Exception
{
    public ExpiredJwtException(Date expiredAt, Date now)
    {
        super(String.format("Expired at %s and time is now %s", expiredAt, now));
    }
}
