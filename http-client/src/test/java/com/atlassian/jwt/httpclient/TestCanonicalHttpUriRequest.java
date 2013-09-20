package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.JwtUtil;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TestCanonicalHttpUriRequest
{
    @Test
    public void testMethod()
    {
        assertThat(request.getMethod(), is("GET"));
    }

    @Test
    public void testUri()
    {
        assertThat(request.getUri(), is(RELATIVE_URI));
    }

    @Test
    public void testContextPath()
    {
        assertThat(request.getContextPath(), is(CONTEXT_PATH));
    }

    @Test
    public void testQueryParameters()
    {
        assertThat(request.getParameterMap(), is(QUERY_PARAMS));
    }

    private static final Map<String, String[]> QUERY_PARAMS = createQueryParameters();
    private static final String RELATIVE_URI = "/context/path/to/service/";
    private static final String CONTEXT_PATH = "/context";
    private static CanonicalHttpRequest request;

    @BeforeClass
    public static void beforeAllTests() throws UnsupportedEncodingException
    {
        request = new CanonicalHttpUriRequest(createHttpUriRequest(), CONTEXT_PATH);
    }

    private static HttpUriRequest createHttpUriRequest() throws UnsupportedEncodingException
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

    private static Map<String, String[]> createQueryParameters()
    {
        Map<String, String[]> queryParameters = new HashMap<String, String[]>();
        queryParameters.put("zee_last", new String[]{"param"});
        queryParameters.put("repeated", new String[]{"parameter 1","parameter 2"});
        queryParameters.put("first", new String[]{"param"});
        queryParameters.put(JwtConstants.JWT_PARAM_NAME, new String[]{"should.be.ignored"});
        return queryParameters;
    }
}
