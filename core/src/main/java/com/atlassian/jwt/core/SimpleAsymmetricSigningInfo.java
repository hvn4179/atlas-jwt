package com.atlassian.jwt.core;

import com.atlassian.jwt.AsymmetricSigningInfo;
import com.atlassian.jwt.SigningAlgorithm;

import javax.annotation.Nonnull;
import java.security.interfaces.RSAPrivateKey;

/**
 * Created by aroodt on 23/10/2014.
 */
public class SimpleAsymmetricSigningInfo implements AsymmetricSigningInfo
{
    private final SigningAlgorithm signingAlgorithm;
    private final RSAPrivateKey privateKey;

    public SimpleAsymmetricSigningInfo(SigningAlgorithm signingAlgorithm, @Nonnull RSAPrivateKey privateKey)
    {
        this.signingAlgorithm = signingAlgorithm;
        this.privateKey = privateKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey()
    {
        return privateKey;
    }

    @Override
    public SigningAlgorithm getSigningAlgorithm() { return signingAlgorithm; }
}
