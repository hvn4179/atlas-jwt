package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.core.NimbusUtil;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.exception.JwsUnsupportedAlgorithmException;
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

            String prn = NimbusUtil.getStringClaimValue(claims, "prn");
            String alg = NimbusUtil.getStringClaimValue(claims, "alg");

            if (alg == null) {
                throw new JwtParseException("The 'alg' claim is required.");
            }

            return new SimpleJwt(claims.getIssuer(), prn, SigningAlgorithm.forName(alg), jwsObject.getPayload().toString());
        }
        catch (ParseException e)
        {
            throw new JwtParseException(e);
        }
        catch (JwsUnsupportedAlgorithmException e)
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
