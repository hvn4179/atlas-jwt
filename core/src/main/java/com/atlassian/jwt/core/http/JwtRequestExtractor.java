package com.atlassian.jwt.core.http;

import com.atlassian.jwt.CanonicalHttpRequest;

// TODO: name sucks now
public interface JwtRequestExtractor<REQ>
{
    String extractJwt(REQ request);

    CanonicalHttpRequest getCanonicalHttpRequest(REQ request);

}
