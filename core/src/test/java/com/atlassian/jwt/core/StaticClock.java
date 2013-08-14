package com.atlassian.jwt.core;

import java.util.Date;

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
