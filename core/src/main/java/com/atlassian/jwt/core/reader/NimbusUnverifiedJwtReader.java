package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.reader.UnverifiedJwtReader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;

public class NimbusUnverifiedJwtReader implements UnverifiedJwtReader
{

    @Override
    public UnverifiedJwt parse(String jwt) throws JwtParseException
    {
        JWSObject jwsObject = parseJWSObject(jwt);
        try
        {
            JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
            return new SimpleJwt(jwsObject.getHeader().getAlgorithm().getName(), claims.getIssuer(), claims.getSubject(), jwsObject.getPayload().toString());
        }
        catch (ParseException e)
        {
            throw new JwtParseException(e);
        }
    }

    private JWSObject parseJWSObject(String jwt) throws JwtParseException
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
        return jwsObject;
    }

}
