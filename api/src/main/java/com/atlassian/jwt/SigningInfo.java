package com.atlassian.jwt;

import com.google.common.base.Optional;

import java.security.interfaces.RSAPrivateKey;

/**
 * Encapsulates the algorithm and key/secret to be used for signing and verifying jwt tokens
 */
public interface SigningInfo
{
    SigningAlgorithm getSigningAlgorithm();

    Optional<RSAPrivateKey> getPrivateKey();

    Optional<String> getSharedSecret();
}
