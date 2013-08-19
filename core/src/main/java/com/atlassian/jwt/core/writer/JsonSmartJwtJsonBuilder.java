package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import net.minidev.json.JSONObject;

/**
 *
 */
public class JsonSmartJwtJsonBuilder implements JwtJsonBuilder
{
    private final JSONObject json = new JSONObject();

    public JsonSmartJwtJsonBuilder()
    {
        issuedAt(TimeUtil.currentTimeSeconds());
        expirationTime(TimeUtil.currentTimePlusNSeconds(180)); // default JWT lifetime is 3 minutes
    }

    @Override
    public JwtJsonBuilder audience(String aud)
    {
        json.put("aud", aud);
        return this;
    }

    @Override
    public JwtJsonBuilder expirationTime(long exp)
    {
        json.put("exp", exp);
        return this;
    }

    @Override
    public JwtJsonBuilder issuedAt(long iat)
    {
        json.put("iat", iat);
        return this;
    }

    @Override
    public JwtJsonBuilder issuer(String iss)
    {
        json.put("iss", iss);
        return this;
    }

    @Override
    public JwtJsonBuilder jwtId(String jti)
    {
        json.put("jti", jti);
        return this;
    }

    @Override
    public JwtJsonBuilder notBefore(long nbf)
    {
        json.put("nbf", nbf);
        return this;
    }

    @Override
    public JwtJsonBuilder principal(String prn)
    {
        json.put("prn", prn);
        return this;
    }

    @Override
    public JwtJsonBuilder subject(String sub)
    {
        json.put("sub", sub);
        return this;
    }

    @Override
    public JwtJsonBuilder type(String typ)
    {
        json.put("typ", typ);
        return this;
    }

    @Override
    public JwtJsonBuilder claim(String name, Object obj)
    {
        json.put(name, obj);
        return this;
    }

    @Override
    public String build()
    {
        return json.toString();
    }

    @Override
    public String toString()
    {
        return json.toString();
    }
}
