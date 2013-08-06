package com.atlassian.auth.jwt.core;

import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 31/07/13
 * Time: 5:59 PM
 */
public class StaticClock implements Clock
{
    private final Date now;

    public StaticClock(Date now)
    {
        this.now = now;
    }

    @Override
    public Date now()
    {
        return now;
    }
}
