package com.atlassian.auth.jwt.core;

import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 31/07/13
 * Time: 5:58 PM
 */
public class SystemClock implements Clock
{
    private static final Clock INSTANCE = new SystemClock();

    @Override
    public Date now()
    {
        return new Date();
    }

    public static Clock getInstance()
    {
        return INSTANCE;
    }
}
