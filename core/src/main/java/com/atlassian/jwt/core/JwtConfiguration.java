package com.atlassian.jwt.core;

/**
 * Provides configuration details for JWT signature generation and verification.
 *
 * @since 1.0
 */
public interface JwtConfiguration
{
    /**
     * @return the maximum allowed JWT lifetime, in milliseconds. The time between the 'iat' and 'exp' timestamps in a
     *         valid JWT must be less that this number, or the JWT will be rejected.
     */
    long getMaxJwtLifetime();
}
