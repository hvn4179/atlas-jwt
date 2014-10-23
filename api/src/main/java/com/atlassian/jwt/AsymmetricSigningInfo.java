package com.atlassian.jwt;

import java.security.interfaces.RSAPrivateKey;

/**
 * Created by aroodt on 23/10/2014.
 */
public interface AsymmetricSigningInfo extends SigningInfo
{
    RSAPrivateKey getPrivateKey();
}
