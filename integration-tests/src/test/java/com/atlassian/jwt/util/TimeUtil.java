package com.atlassian.jwt.util;

/**
 *
 */
public class TimeUtil
{
    public static long currentTimePlusNSeconds(long n) {
        return System.currentTimeMillis() / 1000 + n;
    }
}
