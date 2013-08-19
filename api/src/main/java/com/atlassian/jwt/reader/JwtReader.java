package com.atlassian.jwt.reader;

import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;

public interface JwtReader
{
    VerifiedJwt verify(String jwt) throws JwtParseException, JwtVerificationException;
}
