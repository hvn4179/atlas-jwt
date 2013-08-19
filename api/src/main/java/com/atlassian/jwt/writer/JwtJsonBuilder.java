package com.atlassian.jwt.writer;

/**
 * Utility for generating JSON payloads for JWTs.
 *
 * @since 1.0
 */
public interface JwtJsonBuilder
{
    JwtJsonBuilder audience(String aud);

    JwtJsonBuilder expirationTime(long exp);

    JwtJsonBuilder issuedAt(long iat);

    JwtJsonBuilder issuer(String iss);

    JwtJsonBuilder jwtId(String jti);

    JwtJsonBuilder notBefore(long nbf);

    JwtJsonBuilder principal(String prn);

    JwtJsonBuilder subject(String sub);

    JwtJsonBuilder type(String typ);

    /**
     * todo doc allowed types for obj
     */
    JwtJsonBuilder claim(String name, Object obj);

    String build();
}
