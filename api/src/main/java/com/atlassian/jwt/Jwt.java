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
     * @return the value of the 'sub' claim. That is, the principal that a request is being executed on the behalf of.
     */
    String getSubject();

    /**
     * @return the value of the {@link JwtConstants.Claims.QUERY_SIGNATURE} custom claim.
     */
    String getQuerySignature();

    /**
     * @return a JSON representation of the claims contained in this JWT.
     */
    String getJsonPayload();
}
