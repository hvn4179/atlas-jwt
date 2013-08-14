package com.atlassian.jwt;

import com.atlassian.jwt.exception.JwtSigningException;

public interface JwtWriter
{
    public String jsonToJwt(String json) throws JwtSigningException;
}
