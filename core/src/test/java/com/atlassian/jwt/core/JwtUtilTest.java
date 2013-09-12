package com.atlassian.jwt.core;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JwtUtilTest
{
    @Test
    public void computeCorrectCanonicalizedQueryFromHttpServletRequest() throws IOException
    {
        assertThat(JwtUtil.canonicalizeQuery(createHttpServletRequest()), is(expectedWhenThereIsNoContextPath()));
    }

    @Test
    public void computeCorrectCanonicalizedQueryFromHttpUriRequest() throws IOException
    {
        assertThat(JwtUtil.canonicalizeQuery(createHttpUriRequest(), ""), is(expectedWhenThereIsNoContextPath()));
    }

    @Test
    public void contextPathIsNotPartOfCanonicalizedRequestFromHttpServletRequest() throws IOException
    {
        String contextPath = "/path";
        String expected = createExpectedCanonicalRequestString(contextPath);

        HttpServletRequest request = createHttpServletRequest();
        when(request.getContextPath()).thenReturn(contextPath);
        assertThat(JwtUtil.canonicalizeQuery(request), is(expected));
    }

    @Test
    public void contextPathIsNotPartOfCanonicalizedRequestFromHttpUriRequest() throws IOException
    {
        String contextPath = "/path";
        String expected = createExpectedCanonicalRequestString(contextPath);

        HttpUriRequest request = createHttpUriRequest();
        assertThat(JwtUtil.canonicalizeQuery(request, contextPath), is(expected));
    }

    private String createExpectedCanonicalRequestString(String contextPath)
    {
        String expected = expectedWhenThereIsAContextPath(contextPath);
        assertThat(RELATIVE_URI, startsWith(contextPath)); // precondition
        assertThat(expected, is(not(expectedWhenThereIsNoContextPath()))); // precondition
        return expected;
    }

    private static String expectedWhenThereIsNoContextPath()
    {
        return createCanonicalRequest(createCanonicalUri());
    }

    private static String expectedWhenThereIsAContextPath(String contextPath)
    {
        return createCanonicalRequest(StringUtils.replaceOnce(createCanonicalUri(), contextPath, ""));
    }

    private static String createCanonicalUri()
    {
        return StringUtils.removeEnd(RELATIVE_URI, "/");
    }

    private static String createCanonicalRequest(String uri)
    {
        return new StringBuilder()
                    .append("GET")
                    .append('&')
                    .append(uri)
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
        when(request.getContextPath()).thenReturn("/");

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
