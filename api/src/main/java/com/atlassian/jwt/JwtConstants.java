package com.atlassian.jwt;

public class JwtConstants
{
    /**
     * When the JWT message is specified in the query string of a URL then this is the parameter name.
     * E.g. "jwt" in "http://server:80/some/path?otherparam=value&jwt=eyJhbGciOiJIUzI1NiIsI.eyJleHAiOjEzNzg5NCI6MTM3ODk1MjQ4OH0.cDihfcsKW_We_EY21tIs55dVwjU"
     */
    public static final String JWT_PARAM_NAME = "jwt";

    public static final class Claims
    {
        /**
         * Instructions for computing the query signature parameter ("qsg") from a HTTP request.
         * -------------------------------------------------------------------------------------
         * Overview:  query signature = sign(canonical-request)
         *          canonical-request = canonical-method + '&' + canonical-URI + '&' + canonical-query-string
         * 1. Compute canonical method.
         *    Simply the upper-case of the method name (e.g. "GET", "PUT").
         * 2. Append the character '&'
         * 3. Compute canonical URI.
         *    Discard the protocol, server, port, context path and query parameters from the full URL.
         *    (Removing the context path allows a reverse proxy to redirect incoming requests for "jira.example.com/getsomething"
         *    to "example.com/jira/getsomething" without breaking authentication. The requester cannot know that the reverse proxy
         *    will prepend the context path "/jira" to the originally requested path "/getsomething".)
         *    Empty-string is not permitted; use "/" instead.
         *    Do not suffix with a '/' character unless it is the only character.
         *    E.g. in "http://server:80/some/path/?param=value" the canonical URI is "/some/path"
         *     and in "http://server:80" the canonical URI is "/".
         * 4. Append the character '&'.
         * 5. Compute the canonical query string.
         *    Sort the query parameters primarily by their percent-encoded names and secondarily by their percent-encoded values.
         *    For each parameter append its percent-encoded name, the '=' character and then its percent-encoded value.
         *    In the case of repeated parameters append the ',' character and subsequent percent-encoded values.
         *    Ignore the {@link JwtConstants.JWT_PARAM_NAME} parameter, if present.
         *    Some particular values to be aware of: "+" is encoded as "%20",
         *                                           "*" as "%2A" and
         *                                           "~" as "~".
         *                                           (These values used for consistency with OAuth1.)
         *    An example: for a GET request to the not-yet-percent-encoded URL "http://localhost:2990/path/to/service?zee_last=param&repeated=parameter 1&first=param&repeated=parameter 2"
         *    the canonical request is "GET&/path/to/service&first=param&repeated=parameter%201,parameter%202&zee_last=param".
         * 6. Convert the canonical request string to bytes.
         *    The encoding used to represent characters as bytes is UTF-8.
         * 7. Sign the canonical request bytes using the same signing algorithm and other signing inputs (such a shared secret) used to sign the whole JWT.
         *    E.g.   if you can compute jwtSignature = sign(base-64-encoded-JWT-header + '.' + base-64-encoded-JWT-claims)
         *       then you can compute querySignature = sign(canonical-request-bytes)
         */
        public static final String QUERY_SIGNATURE = "qsg";
    }
}
