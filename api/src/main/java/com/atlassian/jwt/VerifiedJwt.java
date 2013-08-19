package com.atlassian.jwt;

/**
 * A {@link Jwt} that has had its signature verified. The {@link #getJsonPayload() payload} can be trusted.
 *
 * @since 1.0
 */
public interface VerifiedJwt extends Jwt
{
}
