package com.atlassian.jwttest.rest;

public class RequestSubjectStore
{
    private static String subject = null;

    public static String getSubject()
    {
        return subject;
    }

    public static void setSubject(String subject)
    {
        RequestSubjectStore.subject = subject;
    }
}
