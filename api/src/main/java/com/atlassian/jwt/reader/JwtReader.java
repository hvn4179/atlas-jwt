package com.atlassian.jwt.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;

import java.util.Map;

/**
 * Parses and verifies {@link Jwt}s attached to incoming requests.
 *
 * @since 1.0
 */
public interface JwtReader
{
    /**
     *
     * @param jwt a JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     * @param requiredClaims claims that must be present, the specified values
     * @return a verified {@link Jwt}
     * @throws JwtParseException        if the JWT string was malformed
     * @throws JwtVerificationException if the JWT string was well-formed but failed verification
     */
    Jwt verify(String jwt, Map<String, JwtClaimVerifier> requiredClaims) throws JwtParseException, JwtVerificationException;

    /**
     * Construct an object that can verify a signed claim against a particular input.
     * @param signingInput input to the signing and verification algorithms
     * @param claimName the claim's JSON key
     * @return a {@link JwtClaimVerifier} capable of verifying claimed signatures of this input
     */
    JwtClaimVerifier createSignedClaimVerifier(String signingInput, String claimName);
}
