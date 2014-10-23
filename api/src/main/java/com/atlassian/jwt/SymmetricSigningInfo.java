package com.atlassian.jwt;

/**
 * Created by aroodt on 23/10/2014.
 */
public interface SymmetricSigningInfo extends SigningInfo
{
    String getSharedSecret();
}
