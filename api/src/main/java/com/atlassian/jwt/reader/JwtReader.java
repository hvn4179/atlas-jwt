package com.atlassian.jwt.reader;

import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;

/**
 * Parses and verifies {@link VerifiedJwt JWTs} attached to incoming requests.
 *
 * @since 1.0
 */
public interface JwtReader
{
    /**
     * @param jwt a JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     * @return a verified {@link VerifiedJwt JWT}
     * @throws JwtParseException if the JWT string was malformed
     * @throws JwtVerificationException if the JWT string was well-formed but failed verification
     */
    VerifiedJwt verify(String jwt) throws JwtParseException, JwtVerificationException;
}
