package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.core.JwtUtil;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.http.client.methods.HttpUriRequest;

import java.util.*;

public class CanonicalHttpUriRequest implements CanonicalHttpRequest
{
    private final HttpUriRequest request;
    private final String contextPath;
    private final Map<String, String[]> parameterMap;

    public CanonicalHttpUriRequest(final HttpUriRequest request, final String contextPath)
    {
        this.request = request;
        this.contextPath = contextPath;
        this.parameterMap = constructParameterMap(request);
    }

    @Override
    public String getMethod()
    {
        return request.getMethod();
    }

    @Override
    public String getResourcePath()
    {
        return request.getURI().getPath();
    }

    @Override
    public String getContextPath()
    {
        return contextPath;
    }

    @Override
    public Map<String, String[]> getParameterMap()
    {
        return parameterMap;
    }

    private static Map<String, String[]> constructParameterMap(HttpUriRequest request)
    {
        List<NameValuePair> queryParams = new ParameterParser().parse(request.getURI().getQuery(), JwtUtil.QUERY_PARAMS_SEPARATOR);
        Multimap<String, String> queryParamsMapIntermediate = HashMultimap.<String, String>create(queryParams.size(), 1); // 1 value per key is close to the truth in most cases

        // efficiently collect { name1 -> { value1, value2, ... }, name2 -> { ... }, ... }
        for (NameValuePair nameValuePair : queryParams)
        {
            queryParamsMapIntermediate.put(nameValuePair.getName(), nameValuePair.getValue());
        }

        Map<String, String[]> queryParamsMap = new HashMap<String, String[]>(queryParamsMapIntermediate.size());

        // convert String -> Collection<String> to String -> String[]
        for (Map.Entry<String, Collection<String>> entry : queryParamsMapIntermediate.asMap().entrySet())
        {
            queryParamsMap.put(entry.getKey(), entry.getValue().toArray(new String[entry.getValue().size()]));
        }

        return queryParamsMap;
    }
}
