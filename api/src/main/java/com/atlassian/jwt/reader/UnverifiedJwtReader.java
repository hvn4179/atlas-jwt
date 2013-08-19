package com.atlassian.jwt.reader;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.exception.JwtParseException;

/**
 * Parses {@link UnverifiedJwt JWTs} from incoming requests <strong>without attempting verification</strong>.
 * <p/>
 * An unverified reader should only be used to look up the credentials required to verify a particular JWT.
 * <p/>
 * Other data associated with {@link UnverifiedJwt unverified JWTs} must not be trusted. Use {@link JwtReader} instead.
 *
 * @since 1.0
 */
public interface UnverifiedJwtReader
{
    /**
     * @param jwt an JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
     * @return an <strong>unverified</strong> {@link UnverifiedJwt JWT}. <strong>DO NOT</strong> trust
     * values associated with this JWT. Use a {@link JwtReader verifying JwtReader} instead.
     * @throws JwtParseException if the JWT string was malformed
     */
    UnverifiedJwt parse(String jwt) throws JwtParseException;
}
