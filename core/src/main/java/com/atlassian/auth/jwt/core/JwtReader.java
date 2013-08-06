package com.atlassian.auth.jwt.core;

import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;

public interface JwtReader
{
    public String jwtToJson(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException;
}
