package com.atlassian.jwt.reader;

import com.atlassian.jwt.exception.*;

/**
 * Factory for {@link JwtReader}.
 *
 * @since 1.0
 */
public interface JwtReaderFactory
{
    /**
     * @param jwt encoded JWT message
     * @return an appropriate {@link JwtReader} for reading this JWT message
     * @throws {@link JwsUnsupportedAlgorithmException} if the JWT message's stated algorithm is not implemented
     * @throws {@link JwtInvalidClaimException} if the JWT message contains a nonsensical claim (e.g. expiry time before issued time)
     * @throws {@link JwtParseException} if the JWT message appears to be mangled
     * @throws {@link JwtUnknownIssuerException} if the JWT message's "iss" claim value is not recognized
     * @throws {@link JwtIssuerLacksSharedSecretException} if the JWT message's algorithm requires a shared secret but the claimed issuer does not have one associated
     */
    JwtReader getReader(String jwt) throws JwsUnsupportedAlgorithmException, JwtInvalidClaimException, JwtUnknownIssuerException, JwtParseException, JwtIssuerLacksSharedSecretException;
}
