package com.atlassian.jwt.httpclient;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.JwtUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
        assertThat(request.getRelativeUri(), is(RELATIVE_URI));
    }

    @Test
    public void testContextPath()
    {
        assertThat(request.getContextPath(), is(CONTEXT_PATH));
    }

    @Test
    public void testQueryParameters()
    {
        assertThat(request.getParameterMap(), isEqualTo(QUERY_PARAMS));
    }

    private static Matcher<Map<String, String[]>> isEqualTo(Map<String, String[]> expected)
    {
        return new IsEquivalentStringToStringArrayMap(expected);
    }

    // because String[].equals(String[]) just tests that the String[]s are the same object
    private static class IsEquivalentStringToStringArrayMap extends TypeSafeMatcher<Map<String, String[]>>
    {
        private final Map<String, String[]> expected;

        public IsEquivalentStringToStringArrayMap(Map<String, String[]> expected)
        {
            this.expected = expected;
        }

        @Override
        protected boolean matchesSafely(Map<String, String[]> actual)
        {
            if (expected.size() != actual.size())
            {
                return false;
            }

            for (Map.Entry<String, String[]> entry : actual.entrySet())
            {
                if (!expected.containsKey(entry.getKey()))
                {
                    return false;
                }

                if (!stringify(expected.get(entry.getKey())).equals(stringify(entry.getValue())))
                {
                    return false;
                }
            }

            return true;
        }

        @Override
        public void describeTo(Description description)
        {
            describeTo(description, expected);
        }

        @Override
        public void describeMismatchSafely(Map<String, String[]> actual, Description description)
        {
            describeTo(description, actual);
        }

        private static void describeTo(Description description, Map<String, String[]> map)
        {
            List<String> keyValuePairs = new ArrayList<String>();

            for (Map.Entry<String, String[]> entry : map.entrySet())
            {
                keyValuePairs.add(String.format("%s=%s", entry.getKey(), StringUtils.join(entry.getValue(), ',')));
            }

            description.appendValueList("<{", ",", "}>", keyValuePairs);
        }

        private String stringify(String[] strings)
        {
            return StringUtils.join(strings, ',');
        }
    }

    private static final Map<String, String[]> QUERY_PARAMS = createExpectedQueryParameters();
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

    private static Map<String, String[]> createExpectedQueryParameters()
    {
        Map<String, String[]> queryParameters = new HashMap<String, String[]>();
        queryParameters.put("zee_last", new String[]{"param"});
        queryParameters.put("repeated", new String[]{"parameter 1","parameter 2"});
        queryParameters.put("first", new String[]{"param"});
        queryParameters.put(JwtConstants.JWT_PARAM_NAME, new String[]{"should.be.ignored"});
        return queryParameters;
    }
}
