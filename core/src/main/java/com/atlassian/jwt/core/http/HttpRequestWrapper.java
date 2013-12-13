package com.atlassian.jwt.core.http;

import com.google.common.base.Optional;

public interface HttpRequestWrapper
{
    Optional<String> getParameter(String parameterName);

    Iterable<String> getHeaderValues(String headerName);
}
