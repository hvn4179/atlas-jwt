package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtInvalidClaimException;
import com.atlassian.jwt.reader.JwtClaimVerifier;

import java.util.Objects;

public class JwtClaimEqualityVerifier implements JwtClaimVerifier
{
    private final Object expectedValue;

    public JwtClaimEqualityVerifier(Object expectedValue)
    {
        this.expectedValue = expectedValue;
    }

    @Override
    public void verify(Object claim) throws JwtInvalidClaimException
    {
        if (!Objects.equals(expectedValue, claim))
        {
            throw new JwtInvalidClaimException(String.format("Expecting claim to have value '%s' but instead it has the value '%s'", expectedValue, claim));
        }
    }
}
