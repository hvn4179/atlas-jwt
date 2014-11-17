package com.atlassian.jwt.core.keys;

import com.atlassian.jwt.exception.JwtCannotRetrieveKeyException;

import java.security.interfaces.RSAPrivateKey;

public interface PrivateKeyRetriever
{
    public enum keyLocationType
    {
        FILE, CLASSPATH_RESOURCE
    }

    public RSAPrivateKey getPrivateKey() throws JwtCannotRetrieveKeyException;
}