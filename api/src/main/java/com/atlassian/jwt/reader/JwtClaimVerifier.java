package com.atlassian.jwt.reader;

import com.atlassian.jwt.exception.JwtVerificationException;

public interface JwtClaimVerifier
{
    public void verify(Object claim) throws JwtVerificationException;
}
