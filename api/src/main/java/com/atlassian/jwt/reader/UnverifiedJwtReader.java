package com.atlassian.jwt.reader;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.exception.JwtParseException;

public interface UnverifiedJwtReader
{
    UnverifiedJwt parse(String jwt) throws JwtParseException;
}
