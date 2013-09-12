package com.atlassian.jwt;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * HTTP request that can be signed for use as a JWT claim.
 *
 * @since 1.0
 */
public interface CanonicalHttpRequest
{
    /**
     * Assemble the components of the HTTP request into the correct format so that they can be signed.
     * See {@link JwtConstants.Claims.QUERY_SIGNATURE} for a detailed description of how to compute the signature.
     * @return {@link String} representing the canonical form of the HTTP request
     * @throws IOException
     */
    public String canonicalize() throws UnsupportedEncodingException;
}
