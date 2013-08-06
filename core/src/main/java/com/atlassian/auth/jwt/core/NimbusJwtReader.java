package com.atlassian.auth.jwt.core;

import com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;

/**
 * Author: pbrownlow
 * Date: 30/07/13
 * Time: 5:15 PM
 */
public class NimbusJwtReader implements JwtReader
{
    private final JWSVerifier verifier;
    private final Clock clock;

    public NimbusJwtReader(JWSVerifier verifier)
    {
        this(verifier, SystemClock.getInstance());
    }

    public NimbusJwtReader(JWSVerifier verifier, Clock clock)
    {
        this.verifier = verifier;
        this.clock = clock;
    }

    @Override
    public String jwtToJson(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException
    {
        JWSObject jwsObject;

        // Parse back and check signature
        try
        {
            jwsObject = JWSObject.parse(jwt);

        }
        catch (ParseException e)
        {
            throw new JwtParseException(e);
        }

        boolean verifiedSignature;

        try
        {
            verifiedSignature = jwsObject.verify(verifier);

        }
        catch (JOSEException e)
        {
            throw new JwtSignatureMismatchException(e);
        }

        if (!verifiedSignature)
        {
            throw new JwtSignatureMismatchException(jwt);
        }

        JSONObject jsonPayload = jwsObject.getPayload().toJSONObject();
        JWTClaimsSet claims;

        try
        {
            claims = JWTClaimsSet.parse(jsonPayload);
        }
        catch (ParseException e)
        {
            throw new JwtParseException(e);
        }

        Date now = clock.now();

        if (claims.getExpirationTime().before(now))
        {
            throw new ExpiredJwtException(claims.getExpirationTime(), now);
        }

        return jsonPayload.toString();
    }

    @Override
    public String getIssuer(String json) throws JwtParseException
    {
        final Object jsonObject = JSONValue.parse(json);

        if (!(jsonObject instanceof JSONObject))
        {
            throw new JwtParseException("Expecting JWT body to contain a JSON object but instead found " + (jsonObject == null ? "null" : jsonObject.getClass().getSimpleName()));
        }

        try
        {
            JWTClaimsSet claimsSet = JWTClaimsSet.parse((JSONObject)jsonObject);
            return claimsSet.getIssuer();
        }
        catch (ParseException e)
        {
            throw new JwtParseException(e);
        }
    }
}
