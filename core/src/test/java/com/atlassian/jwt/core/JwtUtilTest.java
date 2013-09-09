package com.atlassian.jwt.core;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JwtUtilTest
{
    @Test
    public void computeCorrectCanonicalizedQueryFromHttpServletRequest() throws IOException
    {
        assertThat(JwtUtil.canonicalizeQuery(createHttpServletRequest()), is(expected()));
    }

    @Test
    public void computeCorrectCanonicalizedQueryFromHttpUriRequest() throws IOException
    {
        assertThat(JwtUtil.canonicalizeQuery(createHttpUriRequest()), is(expected()));
    }

    private String expected()
    {
        return new StringBuilder()
                    .append("GET")
                    .append('&')
                    .append("/path/to/service")
                    .append('&')
                    .append("first=param&repeated=parameter%201,parameter%202&zee_last=param")
                    .toString();
    }

    private static final Map<String, String[]> QUERY_PARAMS = createQueryParameters();
    private static final String RELATIVE_URI = "/path/to/service/";

    private HttpUriRequest createHttpUriRequest() throws UnsupportedEncodingException
    {
        StringBuilder queryParams = new StringBuilder();

        for (Map.Entry<String, String[]> param : QUERY_PARAMS.entrySet())
        {
            for (String paramValue : param.getValue())
            {
                if (queryParams.length() > 0)
                {
                    queryParams.append('&');
                }

                queryParams.append(param.getKey())
                        .append('=')
                        .append(paramValue);
            }
        }

        return new HttpGet("http://server:port" + RELATIVE_URI + '?' + JwtUtil.percentEncode(queryParams.toString()));
    }

    private HttpServletRequest createHttpServletRequest()
    {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn(RELATIVE_URI);
        when(request.getParameterMap()).thenReturn(QUERY_PARAMS);

        return request;
    }

    private static Map<String, String[]> createQueryParameters()
    {
        Map<String, String[]> queryParameters = new HashMap<String, String[]>();
        queryParameters.put("zee_last", new String[]{"param"});
        queryParameters.put("repeated", new String[]{"parameter 1","parameter 2"});
        queryParameters.put("first", new String[]{"param"});
        queryParameters.put(JwtUtil.JWT_PARAM_NAME, new String[]{"should.be.ignored"});
        return queryParameters;
    }
}
