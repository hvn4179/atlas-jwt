package com.atlassian.jwt;

import com.atlassian.jwt.exception.JwtParseException;

public interface JwtParser
{
    Jwt parse(String jwt) throws JwtParseException;
}
