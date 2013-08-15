package com.atlassian.jwt;

/**
 * A JSON Web Token.
 */
public interface Jwt
{
    String getIssuer();

    String getPrincipal();

    SigningAlgorithm getSigningAlgorithm();

    String getJsonPayload();
}
