package com.atlassian.jwt.httpclient;

import java.util.Map;


import com.atlassian.jwt.CanonicalHttpRequest;
import com.google.common.base.Joiner;
import com.google.common.base.Objects;

public class CanonicalRequestUtil
{
    // So we can share between different impls.
    // Likely too large to be a useful toString
    public static String toVerboseString(CanonicalHttpRequest request)
    {
        return Objects.toStringHelper(request)
                .add("method", request.getMethod())
                .add("relativePath", request.getRelativePath())
                .add("parameterMap", mapToString(request.getParameterMap()))
                .toString();
    }

    private static String mapToString(Map<String, String[]> parameterMap)
    {
        StringBuilder sb = new StringBuilder()
                .append('[');

        for (Map.Entry<String, String[]> entry : parameterMap.entrySet())
        {
            sb.append(entry.getKey()).append(" -> ");
            String[] value = entry.getValue();
            if (value != null)
            {
                sb.append("(");
                Joiner.on(",").appendTo(sb, value);
                sb.append(")");
            }
            sb.append(','); // I know being lazy
        }

        return sb.append(']')
                .toString();
    }

}
