package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
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
import java.util.Calendar;
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
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.SECOND, -JwtConstants.TIME_CLAIM_LEEWAY_SECONDS);
        Date nowMinusLeeway = calendar.getTime();
        calendar.setTime(now);
        calendar.add(Calendar.SECOND, JwtConstants.TIME_CLAIM_LEEWAY_SECONDS);
        Date nowPlusLeeway = calendar.getTime();

        if (null != claims.getNotBeforeTime())
        {
            // sanity check: if the token is invalid before, on and after a given time then it is always invalid and the issuer has made a mistake
            if (!claims.getExpirationTime().after(claims.getNotBeforeTime()))
            {
                throw new JwtInvalidClaimException(String.format("The expiration time must be after the not-before time but exp=%s and nbf=%s", claims.getExpirationTime(), claims.getNotBeforeTime()));
            }

            if (claims.getNotBeforeTime().after(nowPlusLeeway))
            {
                throw new JwtTooEarlyException(claims.getNotBeforeTime(), now, JwtConstants.TIME_CLAIM_LEEWAY_SECONDS);
            }
        }

        if (claims.getExpirationTime().before(nowMinusLeeway))
        {
            throw new JwtExpiredException(claims.getExpirationTime(), now, JwtConstants.TIME_CLAIM_LEEWAY_SECONDS);
        }

        for (Map.Entry<String, ? extends JwtClaimVerifier> requiredClaim : requiredClaims.entrySet())
        {
            requiredClaim.getValue().verify(claims.getClaim(requiredClaim.getKey()));
        }

        return new SimpleJwt(claims.getIssuer(), claims.getSubject(), jsonPayload.toString());
    }
}
