package com.atlassian.jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 */
public interface JwtIssuerRegistry
{
    @Nullable
    JwtIssuer getIssuer(@Nonnull String issuer);
}
