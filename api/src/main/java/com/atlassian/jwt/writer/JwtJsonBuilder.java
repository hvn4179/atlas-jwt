package com.atlassian.jwt.writer;

import java.util.Map;

/**
 * Utility for generating JSON payloads for JWTs.
 *
 * @since 1.0
 */
public interface JwtJsonBuilder
{
    /**
     * Sets the 'aud' parameter.
     */
    JwtJsonBuilder audience(String aud);

    /**
     * Sets the 'exp' parameter.
     */
    JwtJsonBuilder expirationTime(long exp);

    /**
     * Sets the 'iat' parameter.
     */
    JwtJsonBuilder issuedAt(long iat);

    /**
     * Sets the 'iss' parameter.
     */
    JwtJsonBuilder issuer(String iss);

    /**
     * Sets the 'jti' parameter.
     */
    JwtJsonBuilder jwtId(String jti);

    /**
     * Sets the 'nbf' parameter.
     */
    JwtJsonBuilder notBefore(long nbf);

    /**
     * Sets the 'prn' parameter.
     */
    JwtJsonBuilder principal(String prn);

    /**
     * Sets the 'sub' parameter.
     */
    JwtJsonBuilder subject(String sub);

    /**
     * Sets the 'typ' parameter.
     */
    JwtJsonBuilder type(String typ);

    /**
     * Adds an arbitrary claim.
     *
     * @param name the claim's name.
     * @param obj the claim's value. Allowed types are:
     *            <ul>
     *              <li>{@link String}</li>
     *              <li>{@link Boolean}</li>
     *              <li>{@link Number}</li>
     *              <li>a {@link Map} of {@link String} to any of the above</li>
     *              <li>an array of any of the above</li>
     *            </ul>
     */
    JwtJsonBuilder claim(String name, Object obj);

    /**
     * @return the generated JSON.
     */
    String build();
}
