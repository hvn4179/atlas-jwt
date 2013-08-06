package com.atlassian.auth.jwt.core;

import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.JwtSigningException;

public interface JwtWriter
{
    public String jsonToJwt(String json) throws JwtSigningException;
}
