package com.atlassian.jwt.applinks;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.atlassian.applinks.api.ApplicationLink;

public interface JwtApplinkFinder
{
    /**
     * Find an {@link com.atlassian.applinks.api.ApplicationLink} with the given add-on id that uses JWT authentication.
     * @param addOnId AKA the "plugin key"
     * @return the first matching {@link com.atlassian.applinks.api.ApplicationLink} or null if there are no matches
     * @throws IllegalArgumentException if the id argument is null
     */
    @Nullable
    ApplicationLink find(@Nonnull String addOnId);
}
