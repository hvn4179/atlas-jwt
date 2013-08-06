package com.atlassian.auth.jwt.core;

import com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;

// Avoid leaking which JSON and JWT APIs are used in implementations.
public interface JwtReader
{
    public String jwtToJson(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException;
    public String getIssuer(String json) throws JwtParseException;
}
