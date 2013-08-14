package com.atlassian.jwt.applinks;

public class NotAJwtPeerException extends RuntimeException
{

    public NotAJwtPeerException(String message)
    {
        super(message);
    }

}
