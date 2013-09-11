package com.atlassian.jwt.reader;

import com.atlassian.jwt.exception.JwtVerificationException;

/**
 * Interface for asserting that a JWT claim is valid.
 * Implementations include straightforward equality checking and verification of signatures.
 */
public interface JwtClaimVerifier
{
    /**
     * Assert that the claimed value is valid.
     * @param claim The value of the JWT claim.
     * @throws JwtVerificationException if the claim is invalid or could not be verified
     */
    public void verify(Object claim) throws JwtVerificationException;
}
