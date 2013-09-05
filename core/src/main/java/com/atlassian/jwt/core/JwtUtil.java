package com.atlassian.jwt.core;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.exception.JwtSigningException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import org.apache.commons.lang.StringUtils;

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
        char separator = '&';
        return new StringBuilder()
                .append(canonicalizeRequestMethod(request))
                .append(separator)
                .append(canonicalizeRequestUri(request))
                .append(separator)
                .append(canonicalizeQueryParameters(request))
                .toString();
    }

    private static String canonicalizeRequestUri(HttpServletRequest request)
    {
        return StringUtils.defaultIfBlank(StringUtils.removeEnd(request.getRequestURI(), "/"), "/");
    }

    private static String canonicalizeRequestMethod(HttpServletRequest request)
    {
        return StringUtils.upperCase(request.getMethod());
    }

    private static String canonicalizeQueryParameters(HttpServletRequest request) throws IOException
    {
        String result = "";
        Map<String, String[]> parameterMap = request.getParameterMap();

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
                    into.write('&');
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

    private static String percentEncode(String s)
    {
        if (s == null)
        {
            return "";
        }
        try
        {
            return URLEncoder.encode(s, ENCODING)
                    // encodes some characters differently to URLEncoder
                    // to match OAuth1 and VisualVault
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
        }
        catch (UnsupportedEncodingException wow)
        {
            throw new RuntimeException(wow.getMessage(), wow);
        }
    }

    private static final String safeToString(Object from)
    {
        return null == from ? null : from.toString();
    }

    /**
     * An efficiently sortable wrapper around a parameter.
     */
    private static class ComparableParameter implements Comparable<ComparableParameter>
    {
        ComparableParameter(Map.Entry<String, String[]> parameter)
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
