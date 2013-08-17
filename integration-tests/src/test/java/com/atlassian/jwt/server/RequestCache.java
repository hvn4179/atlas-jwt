package com.atlassian.jwt.server;

/**
 *
 */
public class RequestCache
{
    private String mostRecentPayload;

    public String getMostRecentPayload()
    {
        return mostRecentPayload;
    }

    public void setMostRecentPayload(String mostRecentPayload)
    {
        this.mostRecentPayload = mostRecentPayload;
    }
}
