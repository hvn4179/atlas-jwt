package com.atlassian.jwt;

/**
 * A JSON Web Token.
 *
 * @since 1.0
 */
public interface Jwt
{
    /**
     * @return the value of the 'iss' claim. That is, the principal or application that issued the JWT.
     */
    String getIssuer();

    /**
     * @return the value of the 'prn' claim. That is, the principal that a request is being executed on the behalf of.
     */
    String getPrincipal();

    /**
     * @return a JSON representation of the claims contained in this JWT.
     */
    String getJsonPayload();
}
