package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.exception.JwtInvalidClaimException;
import com.atlassian.jwt.exception.JwtSignatureMismatchException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.util.Base64URL;

import static com.google.common.base.Preconditions.checkNotNull;

public class NimbusJwtClaimSignatureVerifier implements JwtClaimVerifier
{
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final String signingInput;
    private final String claimName; // for meaningful exception text

    public NimbusJwtClaimSignatureVerifier(JWSVerifier verifier, JWSAlgorithm algorithm, String signingInput, String claimName)
    {
        this.verifier = checkNotNull(verifier);
        this.algorithm = checkNotNull(algorithm);
        this.signingInput = checkNotNull(signingInput);
        this.claimName = checkNotNull(claimName);
    }

    @Override
    public void verify(Object claim) throws JwtVerificationException
    {
        try
        {
            if (null == claim)
            {
                throw new JwtInvalidClaimException(String.format("Claim '%s' is null; it is probably missing from the JWT. Please add it.", claimName));
            }

            String claimedSignature = claim.toString();

            if (!verifier.verify(new JWSHeader(algorithm), signingInput.getBytes(), new Base64URL(claimedSignature)))
            {
                throw new JwtSignatureMismatchException(String.format("Claimed signature '%s' fails verification using algorithm '%s' and signing input '%s'",
                        claimedSignature, algorithm.getName(), signingInput));
            }
        }
        catch (JOSEException e)
        {
            throw new JwtSignatureMismatchException(e);
        }
    }
}
