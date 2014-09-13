package com.atlassian.jwt.core.keys;

import com.atlassian.fugue.Either;
import com.atlassian.jwt.exception.JwtCannotRetrieveKeyException;

import java.security.interfaces.RSAPrivateKey;

public interface PrivateKeyRetriever
{
    public enum keyLocationType {
        FILE, HTTP_URL, CLASSPATH_RESOURCE
    }

    public Either<JwtCannotRetrieveKeyException, RSAPrivateKey> getPrivateKey();
}