package com.atlassian.jwt;

/**
 * A {@link Jwt} that has not yet been verified. The {@link #getJsonPayload() payload} should not be trusted.
 *
 * @since 1.0
 */
public interface UnverifiedJwt extends Jwt
{
    /**
     * @return the raw algorithm specified in the JWT header.
     */
    String getAlgorithm();
}
