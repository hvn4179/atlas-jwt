package com.atlassian.jwt.writer;

import com.atlassian.jwt.exception.JwtSigningException;

public interface JwtWriter
{
    String jsonToJwt(String json) throws JwtSigningException;
}
