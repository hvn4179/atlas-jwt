package com.atlassian.auth.jwt.serviceprovider;

import com.atlassian.auth.jwt.core.Clock;

import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 6/08/13
 * Time: 10:04 AM
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
