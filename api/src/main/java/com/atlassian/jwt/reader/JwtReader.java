package com.atlassian.jwt.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;

import javax.annotation.Nonnull;
import java.util.Map;

/**
 * Parses and verifies {@link Jwt}s attached to incoming requests.
 *
 * @since 1.0
 */
public interface JwtReader
{
    /**
     * Parses the encoded JWT message from {@link String}, verifies its signature (if there is one) and on success returns the decoded {@link Jwt}.
     *
     * @param jwt            a JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     * @param requiredClaims claims that must be present, the specified values
     * @return a verified {@link Jwt}
     * @throws JwtParseException        if the JWT string was malformed
     * @throws JwtVerificationException if the JWT string was well-formed but failed verification
     */
    @Nonnull
    Jwt read(@Nonnull String jwt, @Nonnull Map<String, ? extends JwtClaimVerifier> requiredClaims) throws JwtParseException, JwtVerificationException;
}
