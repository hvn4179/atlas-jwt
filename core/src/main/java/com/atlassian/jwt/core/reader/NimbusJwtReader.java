package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;

import javax.annotation.Nonnull;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

public class NimbusJwtReader implements JwtReader
{
    private final JWSVerifier verifier;
    private final Clock clock;

    public NimbusJwtReader(JWSVerifier verifier, Clock clock)
    {
        this.verifier = verifier;
        this.clock = clock;
    }

    @Nonnull
    @Override
    public Jwt read(@Nonnull String jwt, @Nonnull Map<String, ? extends JwtClaimVerifier> requiredClaims) throws JwtParseException, JwtVerificationException
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

        if (claims.getIssueTime() == null || claims.getExpirationTime() == null)
        {
            throw new JwtInvalidClaimException("'exp' and 'iat' are required claims. Atlassian JWT does not allow JWTs with " +
                    "unlimited lifetimes.");
        }

        Date now = clock.now();

        if (claims.getExpirationTime().before(now))
        {
            throw new JwtExpiredException(claims.getExpirationTime(), now);
        }

        if (null != claims.getNotBeforeTime() && claims.getNotBeforeTime().after(now))
        {
            throw new JwtTooEarlyException(claims.getNotBeforeTime(), now);
        }

        for (Map.Entry<String, ? extends JwtClaimVerifier> requiredClaim : requiredClaims.entrySet())
        {
            requiredClaim.getValue().verify(claims.getClaim(requiredClaim.getKey()));
        }

        return new SimpleJwt(claims.getIssuer(), claims.getSubject(), jsonPayload.toString());
    }
}
