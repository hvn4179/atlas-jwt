package com.atlassian.jwt.reader;

import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.exception.ExpiredJwtException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtSignatureMismatchException;

public interface JwtReader
{
    VerifiedJwt verify(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException;
}
