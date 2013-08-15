package com.atlassian.jwt;

/**
 * An {@link Jwt} that has not yet been verified. The {@link #getJsonPayload() payload} should not be trusted.
 */
public interface UnverifiedJwt extends Jwt
{
}
