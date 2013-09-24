package com.atlassian.jwt.core;

import com.atlassian.jwt.CanonicalHttpRequest;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TestHttpRequestCanonicalizer
{
    @Test
    public void computeCorrectCanonicalizedQuery() throws UnsupportedEncodingException
    {
        assertThat(HttpRequestCanonicalizer.canonicalize(REQUEST), is(EXPECTED));
    }

    @Test
    public void computeCorrectCanonicalQueryWhenThereIsNoContextPath() throws UnsupportedEncodingException
    {
        assertThat(HttpRequestCanonicalizer.canonicalize(REQUEST_WITH_NO_CONTEXT_PATH), is(EXPECTED_WHEN_THERE_IS_NO_CONTEXT_PATH));
    }

    @Test
    public void computeCorrectCanonicalizedQueryWhenThereAreRepeatedParameters() throws UnsupportedEncodingException
    {
        assertThat(HttpRequestCanonicalizer.canonicalize(REQUEST_WITH_REPEATED_PARAMS), is(EXPECTED_WHEN_THERE_ARE_REPEATED_PARAMS));
    }

    @Test
    public void computeCorrectCanonicalizedQueryWhenThereAreNoParameters() throws UnsupportedEncodingException
    {
        assertThat(HttpRequestCanonicalizer.canonicalize(REQUEST_WITH_NO_PARAMS), is(EXPECTED_WHEN_THERE_ARE_NO_PARAMS));
    }

    @Test
    public void computeCorrectCanonicalizedQueryWhenThereAreManyParameters() throws UnsupportedEncodingException
    {
        assertThat(HttpRequestCanonicalizer.canonicalize(REQUEST_WITH_MANY_PARAMS), is(EXPECTED_WHEN_THERE_ARE_MANY_PARAMS));
    }

    private final static String EXPECTED = "GET&/and/more&foo=bah";
    private final static String EXPECTED_WHEN_THERE_IS_NO_CONTEXT_PATH = "PUT&/simple&foo=bah";
    private final static String EXPECTED_WHEN_THERE_ARE_REPEATED_PARAMS = "POST&/simple&foo=bah,humbug";
    private final static String EXPECTED_WHEN_THERE_ARE_NO_PARAMS = "GET&/simple&";
    private final static String EXPECTED_WHEN_THERE_ARE_MANY_PARAMS = "GET&/and/more&first=param1&foo=bah,humbug&last=param%201,param%202";

    private final static CanonicalHttpRequest REQUEST = new CanonicalHttpRequest()
    {
        @Override
        public String getMethod()
        {
            return "GET";
        }

        @Override
        public String getResourcePath()
        {
            return "/context/and/more/";
        }

        @Override
        public String getContextPath()
        {
            return "/context";
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            return Collections.singletonMap("foo", new String[]{"bah"});
        }
    };

    private static final CanonicalHttpRequest REQUEST_WITH_NO_CONTEXT_PATH = new CanonicalHttpRequest()
    {
        @Override
        public String getMethod()
        {
            return "PUT";
        }

        @Override
        public String getResourcePath()
        {
            return "/simple";
        }

        @Override
        public String getContextPath()
        {
            return "/";
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            return Collections.singletonMap("foo", new String[]{"bah"});
        }
    };

    private static final CanonicalHttpRequest REQUEST_WITH_REPEATED_PARAMS = new CanonicalHttpRequest()
    {
        @Override
        public String getMethod()
        {
            return "POST";
        }

        @Override
        public String getResourcePath()
        {
            return "/simple";
        }

        @Override
        public String getContextPath()
        {
            return "/";
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            return Collections.singletonMap("bah", new String[]{ "humbug", "bah" });
        }
    };

    private static final CanonicalHttpRequest REQUEST_WITH_NO_PARAMS = new CanonicalHttpRequest()
    {
        @Override
        public String getMethod()
        {
            return "GET";
        }

        @Override
        public String getResourcePath()
        {
            return "/simple";
        }

        @Override
        public String getContextPath()
        {
            return "/";
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            return Collections.emptyMap();
        }
    };

    private static final CanonicalHttpRequest REQUEST_WITH_MANY_PARAMS = new CanonicalHttpRequest()
    {
        @Override
        public String getMethod()
        {
            return "GET";
        }

        @Override
        public String getResourcePath()
        {
            return "/context/and/more/";
        }

        @Override
        public String getContextPath()
        {
            return "/context";
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            Map<String, String[]> params = new HashMap<String, String[]>();
            params.put("bah", new String[]{ "humbug", "bah" });
            params.put("first", new String[]{ "param1" });
            params.put("last", new String[]{ "param 2", "param 1" });
            return params;
        }
    };
}
