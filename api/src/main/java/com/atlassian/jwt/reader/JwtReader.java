package com.atlassian.jwt.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;

/**
 * Parses and verifies {@link Jwt}s attached to incoming requests.
 *
 * @since 1.0
 */
public interface JwtReader
{
    /**
     * @param jwt a JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     * @return a verified {@link Jwt}
     * @throws JwtParseException        if the JWT string was malformed
     * @throws JwtVerificationException if the JWT string was well-formed but failed verification
     */
    Jwt verify(String jwt) throws JwtParseException, JwtVerificationException;
}
