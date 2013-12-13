package com.atlassian.jwt.core.http;

import javax.annotation.Nullable;

import com.google.common.base.Optional;

public interface HttpRequestWrapper
{
    @Nullable
    String getParameter(String parameterName);

    Iterable<String> getHeaderValues(String headerName);
}
