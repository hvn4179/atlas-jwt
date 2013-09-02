package com.atlassian.jwt.reader;

import com.atlassian.jwt.exception.*;

/**
 * Factory for {@link JwtReader} and {@link UnverifiedJwtReader}.
 *
 * @since 1.0
 */
public interface JwtReaderFactory
{
    /**
     * @param sharedSecret a shared secret suitable for use in an HMAC
     * @return a {@link JwtReader} initialized with the supplied secret.
     */
    JwtReader macVerifyingReader(String sharedSecret);

    /**
     * @return an {@link UnverifiedJwtReader}
     */
    UnverifiedJwtReader unverified();

    JwtReader getReader(String jwt) throws JwsUnsupportedAlgorithmException, JwtInvalidClaimException, JwtUnknownIssuerException, JwtParseException, JwtIssuerLacksSharedSecretException;
}
