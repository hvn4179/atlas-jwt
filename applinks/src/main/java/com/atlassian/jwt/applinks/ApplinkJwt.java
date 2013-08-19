package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.jwt.VerifiedJwt;

/**
 * A {@link VerifiedJwt verified JWT} and the {@link ApplicationLink} that issued it.
 *
 * @since 1.0
 */
public interface ApplinkJwt
{
    /**
     * @return the {@link VerifiedJwt verified JWT}.
     */
    VerifiedJwt getJwt();

    /**
     * @return the {@link ApplicationLink} that issued the JWT.
     */
    ApplicationLink getPeer();
}
