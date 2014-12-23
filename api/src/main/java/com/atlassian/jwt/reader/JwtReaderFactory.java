package com.atlassian.jwt.reader;

import com.atlassian.jwt.AsymmetricSigningInfo;
import com.atlassian.jwt.exception.*;

import javax.annotation.Nonnull;
import java.security.interfaces.RSAPublicKey;

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
     * @throws JwsUnsupportedAlgorithmException if the JWT message's stated algorithm is not implemented
     * @throws JwtParseException if the JWT message appears to be mangled
     * @throws JwtUnknownIssuerException if the JWT message's "iss" claim value is not recognized
     * @throws JwtIssuerLacksSharedSecretException if the JWT message's algorithm requires a shared secret but the claimed issuer does not have one associated
     */
    @Nonnull
    JwtReader getReader(@Nonnull String jwt) throws JwsUnsupportedAlgorithmException, JwtUnknownIssuerException, JwtParseException, JwtIssuerLacksSharedSecretException;


    /**
     *
     * @param jwt encoded JWT message
     * @param publicKey public key to use to verify jwt's signature
     * @return an appropriate {@link JwtReader} for reading this JWT message
     * @throws JwsUnsupportedAlgorithmException if the JWT message's stated algorithm is not implemented
     * @throws JwtParseException if the JWT message appears to be mangled
     */
    @Nonnull
    JwtReader getReader(@Nonnull String jwt, RSAPublicKey publicKey) throws JwsUnsupportedAlgorithmException, JwtParseException;
}
