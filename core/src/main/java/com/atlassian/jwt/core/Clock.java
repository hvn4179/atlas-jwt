package com.atlassian.jwt.core;

import java.util.Date;

public interface Clock
{
    public Date now();
}
