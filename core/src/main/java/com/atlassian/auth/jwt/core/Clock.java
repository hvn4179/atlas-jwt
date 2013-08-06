package com.atlassian.auth.jwt.core;

import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 31/07/13
 * Time: 5:58 PM
 */
public interface Clock
{
    public Date now();
}
