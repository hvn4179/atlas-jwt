package com.atlassian.jwt.reader;

public interface JwtReaderFactory
{
    JwtReader macVerifyingReader(String sharedSecret);

    UnverifiedJwtReader unverified();
}
