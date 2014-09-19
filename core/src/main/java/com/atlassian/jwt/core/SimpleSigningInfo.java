package com.atlassian.jwt.core;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.SigningInfo;
import com.google.common.base.Optional;

import javax.annotation.Nonnull;
import java.security.interfaces.RSAPrivateKey;

/**
 * Information that indicates how tokens will be signed (ie - key/secret + algorithm).
 *
 * The constructors of this class enforce that the algorithm and key/secret type match.
 */
public class SimpleSigningInfo implements SigningInfo
{
    private final SigningAlgorithm signingAlgorithm;
    private final Optional<RSAPrivateKey> privateKey;
    private final Optional<String> sharedSecret;

    public SimpleSigningInfo(SigningAlgorithm signingAlgorithm, @Nonnull RSAPrivateKey privateKey)
    {
        if (signingAlgorithm.requiresSharedSecret())
        {
            throw new IllegalArgumentException("Algorithm requires a private key rather than a shared secret: " + signingAlgorithm);
        }

        this.signingAlgorithm = signingAlgorithm;
        this.privateKey = Optional.of(privateKey);
        this.sharedSecret = Optional.absent();
    }

    public SimpleSigningInfo(SigningAlgorithm signingAlgorithm, @Nonnull String sharedSecret)
    {
        if (signingAlgorithm.requiresKeyPair())
        {
            throw new IllegalArgumentException("Algorithm requires a shared secret rather than a private key: " + signingAlgorithm);
        }

        this.signingAlgorithm = signingAlgorithm;
        this.sharedSecret = Optional.of(sharedSecret);
        this.privateKey = Optional.absent();
    }

    @Override
    public SigningAlgorithm getSigningAlgorithm()
    {
        return signingAlgorithm;
    }

    @Override
    public Optional<RSAPrivateKey> getPrivateKey()
    {
        return privateKey;
    }

    @Override
    public Optional<String> getSharedSecret()
    {
        return sharedSecret;
    }
}
