package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import org.junit.Test;

public class JwtClaimEqualityVerifierTest
{
    private final JwtClaimVerifier claimVerifier = new JwtClaimEqualityVerifier("correct");

    @Test
    public void correctClaimWorks() throws JwtVerificationException
    {
        claimVerifier.verify("correct");
    }

    @Test(expected = JwtVerificationException.class)
    public void incorrectClaimResultsInException() throws JwtVerificationException
    {
        claimVerifier.verify("wrong");
    }
}
