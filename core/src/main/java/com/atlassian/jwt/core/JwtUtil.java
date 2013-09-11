package com.atlassian.jwt.core;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpUriRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

public class JwtUtil
{
    public static final String JWT_PARAM_NAME = "jwt";
    public static final String JWT_REQUEST_FLAG = "com.atlassian.jwt.is-jwt-request";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * The encoding used to represent characters as bytes.
     */
    private static final String ENCODING = "UTF-8";
    /**
     * The character between "a" and "b%20c" in "some_param=a,b%20c"
     */
    private static final char ENCODED_PARAM_VALUE_SEPARATOR = ',';
    /**
     * As appears between "value1" and "param2" in the URL "http://server/path?param1=value1&param2=value2".
     */
    private static final char QUERY_PARAMS_SEPARATOR = '&';

    public static boolean requestContainsJwt(HttpServletRequest request)
    {
        return extractJwt(request) != null;
    }

    public static String extractJwt(HttpServletRequest request)
    {
        String jwt = getJwtParameter(request);
        if (jwt == null)
        {
            jwt = getJwtHeaderValue(request);
        }
        return jwt;
    }

    private static String getJwtParameter(HttpServletRequest request)
    {
        String jwtParam = request.getParameter(JwtUtil.JWT_PARAM_NAME);
        return StringUtils.isEmpty(jwtParam) ? null : jwtParam;
    }

    private static String getJwtHeaderValue(HttpServletRequest request)
    {
        Enumeration<String> headers = request.getHeaders(AUTHORIZATION_HEADER);
        while (headers.hasMoreElements())
        {
            String authzHeader = headers.nextElement().trim();
            String first4Chars = authzHeader.substring(0, Math.min(4, authzHeader.length()));
            if ("JWT ".equalsIgnoreCase(first4Chars))
            {
                return authzHeader.substring(4);
            }
        }
        return null;
    }

    public static String canonicalizeQuery(HttpServletRequest request) throws IOException
    {
        return canonicalizeQuery(canonicalizeRequestMethod(request), canonicalizeRequestUri(request), canonicalizeQueryParameters(request));
    }

    public static String canonicalizeQuery(HttpUriRequest request) throws IOException
    {
        return canonicalizeQuery(canonicalizeRequestMethod(request), canonicalizeRequestUri(request), canonicalizeQueryParameters(request));
    }

    /**
     * {@link URLEncoder}#encode() but encode some characters differently to URLEncoder, to match OAuth1 and VisualVault.
     * @param str {@link String} to be percent-encoded
     * @return encoded {@link String}
     */
    public static String percentEncode(String str) throws UnsupportedEncodingException
    {
        if (str == null)
        {
            return "";
        }

        return URLEncoder.encode(str, ENCODING)
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
    }

    private static String canonicalizeQuery(String canonicalRequestMethod, String canonicalUri, String canonicalQueryParameters)
    {
        return new StringBuilder()
                .append(canonicalRequestMethod)
                .append(QUERY_PARAMS_SEPARATOR)
                .append(canonicalUri)
                .append(QUERY_PARAMS_SEPARATOR)
                .append(canonicalQueryParameters)
                .toString();
    }

    private static String canonicalizeRequestUri(HttpServletRequest request)
    {
        return canonicalizeRelativeRequestUri(request.getRequestURI());
    }

    private static String canonicalizeRequestUri(HttpUriRequest request)
    {
        return canonicalizeRelativeRequestUri(request.getURI().getPath());
    }

    private static String canonicalizeRelativeRequestUri(String uri)
    {
        return StringUtils.defaultIfBlank(StringUtils.removeEnd(uri, "/"), "/");
    }

    private static String canonicalizeRequestMethod(HttpServletRequest request)
    {
        return canonicalizeRequestMethod(request.getMethod());
    }

    private static String canonicalizeRequestMethod(HttpUriRequest request)
    {
        return canonicalizeRequestMethod(request.getMethod());
    }

    private static String canonicalizeRequestMethod(String method)
    {
        return StringUtils.upperCase(method);
    }

    private static String canonicalizeQueryParameters(HttpServletRequest request) throws IOException
    {
        return canonicalizeQueryParameters(request.getParameterMap());
    }

    private static String canonicalizeQueryParameters(HttpUriRequest request) throws IOException
    {
        List<NameValuePair> queryParams = new ParameterParser().parse(request.getURI().getQuery(), QUERY_PARAMS_SEPARATOR);
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

        return canonicalizeQueryParameters(queryParamsMap);
    }

    private static String canonicalizeQueryParameters(Map<String, String[]> parameterMap) throws IOException
    {
        String result = "";

        if (null != parameterMap)
        {
            List<ComparableParameter> parameterList = new ArrayList<ComparableParameter>(parameterMap.size());

            for (Map.Entry<String, String[]> parameter : parameterMap.entrySet())
            {
                if (!JWT_PARAM_NAME.equals(parameter.getKey()))
                {
                    parameterList.add(new ComparableParameter(parameter));
                }
            }

            Collections.sort(parameterList);
            result = formEncode(getParameters(parameterList));
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
    private static String formEncode(Iterable<? extends Map.Entry<String, String[]>> parameters) throws IOException
    {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        formEncode(parameters, b);
        return new String(b.toByteArray());
    }

    /**
     * Write a form-urlencoded document into the given stream, containing the
     * given sequence of name/parameter pairs.
     */
    private static void formEncode(Iterable<? extends Map.Entry<String, String[]>> parameters, OutputStream into) throws IOException
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
                    into.write(QUERY_PARAMS_SEPARATOR);
                }

                into.write(percentEncode(safeToString(parameter.getKey())).getBytes());
                into.write('=');
                List<String> percentEncodedValues = new ArrayList<String>(parameter.getValue().length);

                for (String value : parameter.getValue())
                {
                    percentEncodedValues.add(percentEncode(value));
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
            String name = JwtUtil.safeToString(parameter.getKey());
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
