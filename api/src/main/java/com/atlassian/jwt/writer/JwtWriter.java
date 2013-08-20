package com.atlassian.jwt.writer;

import com.atlassian.jwt.exception.JwtSigningException;

/**
 * Creates JWTs for arbitrary JSON payloads.
 *
 * @since 1.0
 */
public interface JwtWriter
{
    /**
     * @param json a JSON payload.
     * @return a JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     *         containing the supplied payload and an appropriate signature.
     * @throws JwtSigningException if there was a problem signing the payload
     */
    String jsonToJwt(String json) throws JwtSigningException;
}
