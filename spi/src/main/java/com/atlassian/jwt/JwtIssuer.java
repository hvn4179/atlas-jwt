package com.atlassian.jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 *
 */
public interface JwtIssuer
{
    @Nonnull
    String getName();

    @Nullable
    String getSharedSecret();
}
