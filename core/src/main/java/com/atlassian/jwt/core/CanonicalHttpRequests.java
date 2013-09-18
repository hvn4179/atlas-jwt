package com.atlassian.jwt.core;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.JwtConstants;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpUriRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class CanonicalHttpRequests
{
    /**
     * The character between "a" and "b%20c" in "some_param=a,b%20c"
     */
    private static final char ENCODED_PARAM_VALUE_SEPARATOR = ',';
    /**
     * For separating the method, URI etc in a canonical request string.
     */
    private static final char CANONICAL_REQUEST_PART_SEPARATOR = '&';

    private static interface ComposableCanonicalHttpRequest extends CanonicalHttpRequest
    {
        public String getMethod();
        public String getUri();
        public String getContextPath();
        public Map<String, String[]> getParameterMap();
    }

    public static CanonicalHttpRequest from(final HttpServletRequest request)
    {
        return new ComposableCanonicalHttpRequest()
        {
            @Override
            public String getMethod()
            {
                return request.getMethod();
            }

            @Override
            public String getUri()
            {
                return request.getRequestURI();
            }

            @Override
            public String getContextPath()
            {
                return request.getContextPath();
            }

            @Override
            public Map<String, String[]> getParameterMap()
            {
                return request.getParameterMap();
            }

            @Override
            public String canonicalize() throws UnsupportedEncodingException
            {
                return CanonicalHttpRequests.canonicalize(this);
            }
        };
    }

    public static CanonicalHttpRequest from(final HttpUriRequest request, final String contextPath)
    {
        return new ComposableCanonicalHttpRequest()
        {
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

            @Override
            public String canonicalize() throws UnsupportedEncodingException
            {
                return CanonicalHttpRequests.canonicalize(this);
            }
        };
    }

    private static String canonicalize(ComposableCanonicalHttpRequest request) throws UnsupportedEncodingException
    {
        return new StringBuilder()
                .append(canonicalizeMethod(request))
                .append(CANONICAL_REQUEST_PART_SEPARATOR)
                .append(canonicalizeUri(request))
                .append(CANONICAL_REQUEST_PART_SEPARATOR)
                .append(canonicalizeQueryParameters(request))
                .toString();
    }

    private static String canonicalizeUri(ComposableCanonicalHttpRequest request)
    {
        String contextPathToRemove = null == request.getContextPath() || "/".equals(request.getContextPath()) ? "" : request.getContextPath();
        return StringUtils.defaultIfBlank(StringUtils.removeEnd(StringUtils.removeStart(request.getUri(), contextPathToRemove), "/"), "/");
    }

    private static String canonicalizeMethod(ComposableCanonicalHttpRequest request)
    {
        return StringUtils.upperCase(request.getMethod());
    }

    private static String canonicalizeQueryParameters(ComposableCanonicalHttpRequest request) throws UnsupportedEncodingException
    {
        String result = "";

        if (null != request.getParameterMap())
        {
            List<ComparableParameter> parameterList = new ArrayList<ComparableParameter>(request.getParameterMap().size());

            for (Map.Entry<String, String[]> parameter : request.getParameterMap().entrySet())
            {
                if (!JwtConstants.JWT_PARAM_NAME.equals(parameter.getKey()))
                {
                    parameterList.add(new ComparableParameter(parameter));
                }
            }

            Collections.sort(parameterList);
            result = percentEncode(getParameters(parameterList));
        }

        return result;
    }

    /**
     * Retrieve the original parameters from a sorted collection.
     */
    private static List<Map.Entry<String, String[]>> getParameters(Collection<ComparableParameter> parameters)
    {
        if (parameters == null)
        {
            return null;
        }

        List<Map.Entry<String, String[]>> list = new ArrayList<Map.Entry<String, String[]>>(parameters.size());

        for (ComparableParameter parameter : parameters)
        {
            list.add(parameter.parameter);
        }

        return list;
    }

    /**
     * Construct a form-urlencoded document containing the given sequence of
     * name/parameter pairs.
     */
    private static String percentEncode(Iterable<? extends Map.Entry<String, String[]>> parameters)
    {
        ByteArrayOutputStream b = new ByteArrayOutputStream();

        // IOException should not be throws as we are not messing around with it between creation and use
        // (e.g. by closing it) but the methods on the OutputStream interface don't know that
        try
        {
            percentEncode(parameters, b);
            return new String(b.toByteArray());
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Write a form-urlencoded document into the given stream, containing the
     * given sequence of name/parameter pairs.
     */
    private static void percentEncode(Iterable<? extends Map.Entry<String, String[]>> parameters, OutputStream into) throws IOException
    {
        if (parameters != null)
        {
            boolean first = true;

            for (Map.Entry<String, String[]> parameter : parameters)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    into.write(JwtUtil.QUERY_PARAMS_SEPARATOR);
                }

                into.write(JwtUtil.percentEncode(safeToString(parameter.getKey())).getBytes());
                into.write('=');
                List<String> percentEncodedValues = new ArrayList<String>(parameter.getValue().length);

                for (String value : parameter.getValue())
                {
                    percentEncodedValues.add(JwtUtil.percentEncode(value));
                }

                into.write(StringUtils.join(percentEncodedValues, ENCODED_PARAM_VALUE_SEPARATOR).getBytes());
            }
        }
    }

    private static String safeToString(Object from)
    {
        return null == from ? null : from.toString();
    }

    /**
     * An efficiently sortable wrapper around a parameter.
     */
    private static class ComparableParameter implements Comparable<ComparableParameter>
    {
        ComparableParameter(Map.Entry<String, String[]> parameter) throws UnsupportedEncodingException
        {
            this.parameter = parameter;
            String name = safeToString(parameter.getKey());
            String value = StringUtils.join(parameter.getValue(), ',');
            this.key = JwtUtil.percentEncode(name) + ' ' + JwtUtil.percentEncode(value);
            // ' ' is used because it comes before any character
            // that can appear in a percentEncoded string.
        }

        final Map.Entry<String, String[]> parameter;

        private final String key;

        public int compareTo(ComparableParameter that)
        {
            return this.key.compareTo(that.key);
        }

        @Override
        public String toString()
        {
            return key;
        }
    }
}
