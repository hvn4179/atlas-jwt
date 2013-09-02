package com.atlassian.jwt.core;

import com.atlassian.jwt.VerifiedJwt;

/**
 *
 */
public class SimpleJwt implements VerifiedJwt
{
    private final String iss;
    private final String sub;
    private final String payload;

    public SimpleJwt(String iss, String sub, String payload)
    {
        this.iss = iss;
        this.sub = sub;
        this.payload = payload;
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
        return "SimpleJwt{" +
                "iss='" + iss + '\'' +
                ", sub='" + sub + '\'' +
                ", payload='" + payload + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        SimpleJwt simpleJwt = (SimpleJwt) o;

        if (iss != null ? !iss.equals(simpleJwt.iss) : simpleJwt.iss != null)
        {
            return false;
        }
        if (payload != null ? !payload.equals(simpleJwt.payload) : simpleJwt.payload != null)
        {
            return false;
        }
        if (sub != null ? !sub.equals(simpleJwt.sub) : simpleJwt.sub != null)
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = iss != null ? iss.hashCode() : 0;
        result = 31 * result + (sub != null ? sub.hashCode() : 0);
        result = 31 * result + (payload != null ? payload.hashCode() : 0);
        return result;
    }
}
