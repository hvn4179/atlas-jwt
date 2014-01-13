package com.atlassian.jwt.core.http.auth;

/**
 * An authenticator of requests secured by JWT claims for requests of type REQ.
 *
 * @param <REQ> The type of the request
 * @param <RES> The type of the response
 * @param <S>   The type of the status object
 */
public interface JwtAuthenticator<REQ, RES, S>
{
    /**
     * Authenticate the incoming request, returning the status if possible.
     * On bad input or internal failure return a non-success status and return a non-success HTTP response code to
     * {@code response}.
     * Response codes match OAuth:
     * parse error / garbled --> 400 bad request
     * good syntax but purposefully rejected --> 401 unauthorised
     * failure to compute a result --> 500 internal server error
     * rate limiting (not handled here) --> 503 service unavailable
     * default --> 403 forbidden
     *
     * @param request  the request to be vetted
     * @param response the response to be send error code if and only if the authentication is unsuccessful
     * @return a status value representing the success, failure or error of the authentication attempt
     */
    S authenticate(REQ request, RES response);
}
