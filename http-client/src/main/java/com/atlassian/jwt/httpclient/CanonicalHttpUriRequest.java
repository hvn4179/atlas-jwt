package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.core.JwtUtil;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpUriRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CanonicalHttpUriRequest implements CanonicalHttpRequest
{
    private final String method;
    private final String relativePath;
    private final Map<String, String[]> parameterMap;

    private static final Logger log = LoggerFactory.getLogger(CanonicalHttpUriRequest.class);

    public CanonicalHttpUriRequest(final HttpUriRequest request, final String contextPath)
    {
        this.method = request.getMethod();
        String contextPathToRemove = null == contextPath || "/".equals(contextPath) ? "" : contextPath;
        this.relativePath = StringUtils.defaultIfBlank(StringUtils.removeEnd(StringUtils.removeStart(request.getURI().getPath(), contextPathToRemove), "/"), "/");
        this.parameterMap = constructParameterMap(request);
    }

    @Nonnull
    @Override
    public String getMethod()
    {
        return method;
    }

    @Override
    public String getRelativePath()
    {
        return relativePath;
    }

    @Nonnull
    @Override
    public Map<String, String[]> getParameterMap()
    {
        return parameterMap;
    }

    private static Map<String, String[]> constructParameterMap(HttpUriRequest request)
    {
        List queryParams = new ParameterParser().parse(request.getURI().getQuery(), JwtUtil.QUERY_PARAMS_SEPARATOR);
        Multimap<String, String> queryParamsMapIntermediate = HashMultimap.create(queryParams.size(), 1); // 1 value per key is close to the truth in most cases

        // efficiently collect { name1 -> { value1, value2, ... }, name2 -> { ... }, ... }
        for (Object queryParam : queryParams)
        {
            if (queryParam instanceof NameValuePair)
            {
                NameValuePair nameValuePair = (NameValuePair) queryParam;
                queryParamsMapIntermediate.put(nameValuePair.getName(), nameValuePair.getValue());
            }
            else
            {
                log.warn("Ignoring query parameter '{}' that is of type '{}' rather than the expected NameValuePair", queryParam, null == queryParam ? null : queryParam.getClass().getName());
            }
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