package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtInvalidClaimException;
import com.atlassian.jwt.reader.JwtClaimVerifier;

import java.util.Objects;

public class JwtClaimEqualityVerifier implements JwtClaimVerifier
{
    private final String claimName;
    private final Object expectedValue;

    public JwtClaimEqualityVerifier(String claimName, Object expectedValue)
    {
        this.claimName = claimName;
        this.expectedValue = expectedValue;
    }

    @Override
    public void verify(Object claim) throws JwtInvalidClaimException
    {
        if (!Objects.equals(expectedValue, claim))
        {
            throw new JwtInvalidClaimException(String.format("Expecting claim '%s' to have value '%s' but instead it has the value '%s'", claimName, expectedValue, claim));
        }
    }
}
