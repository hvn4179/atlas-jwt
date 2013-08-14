package com.atlassian.jwt;

import com.atlassian.jwt.exception.ExpiredJwtException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtSignatureMismatchException;

public interface JwtReader
{
    String jwtToJson(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException;
    String getIssuer(String json) throws JwtParseException;
}
