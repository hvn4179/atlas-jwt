package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtInvalidClaimException;
import com.atlassian.jwt.exception.JwtMissingClaimException;
import com.atlassian.jwt.reader.JwtClaimVerifier;

import javax.annotation.Nonnull;
import java.util.Objects;

public class JwtClaimEqualityVerifier implements JwtClaimVerifier
{
    private final String claimName;
    private final Object expectedValue;
    private final JwtClaimExistenceVerifier claimExistenceVerifier;

    public JwtClaimEqualityVerifier(String claimName, Object expectedValue)
    {
        this.claimName = claimName;
        this.expectedValue = expectedValue;
        this.claimExistenceVerifier = new JwtClaimExistenceVerifier(claimName);
    }

    @Override
    public void verify(@Nonnull Object claim) throws JwtInvalidClaimException, JwtMissingClaimException
    {
        this.claimExistenceVerifier.verify(claim);

        if (!Objects.equals(expectedValue, claim))
        {
            throw new JwtInvalidClaimException(String.format("Expecting claim '%s' to have value '%s' but instead it has the value '%s'", claimName, expectedValue, claim));
        }
    }
}
