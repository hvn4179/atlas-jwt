package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.core.JwtUtil;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.http.client.methods.HttpUriRequest;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CanonicalHttpUriRequest implements CanonicalHttpRequest
{
    private final HttpUriRequest request;
    private final String contextPath;

    public CanonicalHttpUriRequest(final HttpUriRequest request, final String contextPath)
    {
        this.request = request;
        this.contextPath = contextPath;
    }

    @Override
    public String getMethod()
    {
        return request.getMethod();
    }

    @Override
    public String getUri()
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
        List<NameValuePair> queryParams = new ParameterParser().parse(request.getURI().getQuery(), JwtUtil.QUERY_PARAMS_SEPARATOR);
        Map<String, String[]> queryParamsMap = new HashMap<String, String[]>(queryParams.size());

        for (NameValuePair nameValuePair : queryParams)
        {
            String values[] = queryParamsMap.get(nameValuePair.getName());

            if (null == values)
            {
                values = new String[]{ nameValuePair.getValue() };
            }
            else
            {
                values = Arrays.copyOf(values, values.length + 1);
                values[values.length-1] = nameValuePair.getValue();
            }

            queryParamsMap.put(nameValuePair.getName(), values);
        }

        return queryParamsMap;
    }
}
