package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import net.minidev.json.JSONObject;

import javax.annotation.Nonnull;

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

    @Nonnull
    @Override
    public JwtJsonBuilder audience(@Nonnull String aud)
    {
        json.put("aud", aud);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder expirationTime(long exp)
    {
        json.put("exp", exp);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder issuedAt(long iat)
    {
        json.put("iat", iat);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder issuer(@Nonnull String iss)
    {
        json.put("iss", iss);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder jwtId(@Nonnull String jti)
    {
        json.put("jti", jti);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder notBefore(long nbf)
    {
        json.put("nbf", nbf);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder subject(@Nonnull String sub)
    {
        json.put("sub", sub);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder type(@Nonnull String typ)
    {
        json.put("typ", typ);
        return this;
    }

    @Nonnull
    @Override
    public JwtJsonBuilder queryHash(@Nonnull String qsh)
    {
        json.put("qsh", qsh);
        return this;
    }


    @Nonnull
    @Override
    public JwtJsonBuilder claim(@Nonnull String name, @Nonnull Object obj)
    {
        json.put(name, obj);
        return this;
    }

    @Nonnull
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
