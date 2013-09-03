package com.atlassian.jwt.core;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.VerifiedJwt;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

/**
 *
 */
public class SimpleJwt implements VerifiedJwt, UnverifiedJwt
{
    private final String algorithm;
    private final String iss;
    private final String sub;
    private final String payload;

    public SimpleJwt(String algorithm, String iss, String sub, String payload)
    {
        this.algorithm = algorithm;
        this.iss = iss;
        this.sub = sub;
        this.payload = payload;
    }

    @Override
    public String getAlgorithm()
    {
        return algorithm;
    }

    @Override
    public String getIssuer()
    {
        return iss;
    }

    @Override
    public String getSubject()
    {
        return sub;
    }

    @Override
    public String getJsonPayload()
    {
        return payload;
    }

    @Override
    public String toString()
    {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("algorithm", algorithm)
                .append("iss", iss)
                .append("sub", sub)
                .append("payload", payload)
                .toString();
    }

    @Override
    public boolean equals(Object o)
    {
        if (o == null)
        {
            return false;
        }
        if (o == this)
        {
            return true;
        }
        if (o.getClass() != getClass())
        {
            return false;
        }
        SimpleJwt rhs = (SimpleJwt) o;
        return new EqualsBuilder()
                .append(algorithm, rhs.algorithm)
                .append(iss, rhs.iss)
                .append(sub, rhs.sub)
                .append(payload, rhs.payload)
                .isEquals();
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder(31, 17)
                .append(algorithm)
                .append(iss)
                .append(sub)
                .append(payload)
                .hashCode();
    }
}
