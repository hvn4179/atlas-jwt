package com.atlassian.jwt.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.jwt.applinks.exception.JwtRegistrationFailed;

/**
 * Manages registration and revocation of JWT relationships with remote applications linked to this server via
 * {@link ApplicationLink applinks}.
 *
 * @since 1.0
 */
public interface JwtPeerService
{
    /**
     * Issues an id and shared secret to the specified {@link ApplicationLink} at the supplied path.
     * <p/>
     * The credentials are issued as an HTTP POST with two application/x-www-form-urlencoded form parameters:
     * <ul>
     * <li><strong>id</strong> - an identifier for the linked application to use as the 'iss' field when generating JWTs</li>
     * <li><strong>secret</strong> - a shared secret which should be used to generate HMAC SHA-256 signatures for JWTs</li>
     * </ul>
     * <p/>
     * If the linked application returns an HTTP code outside of the 2xx range the registration process is terminated.
     *
     * @param applicationLink the {@link ApplicationLink linked application} to register an JWT relationship with.
     * @param path            the URI (relative to the {@link ApplicationLink}'s base URL) to POST the credentials to.
     * @throws JwtRegistrationFailed if there was a problem executing the request, or the linked application responded
     *                               with an HTTP code not in the 2xx range.
     */
    void issueSharedSecret(ApplicationLink applicationLink, String path) throws JwtRegistrationFailed;

    /**
     * Delete the JWT credentials associated with the {@link ApplicationLink linked application}. The linked application
     * is not notified during this operation.
     * <p/>
     * This method does nothing if there are no JWT credentials stored for the specified {@link ApplicationLink}.
     *
     * @param applicationLink the {@link ApplicationLink linked application} to delete the JWT credentials for.
     */
    void revokeSharedSecret(ApplicationLink applicationLink);
}
