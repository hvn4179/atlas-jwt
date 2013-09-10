package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.JwtConfiguration;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;

public class NimbusJwtReader implements JwtReader
{
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final Clock clock;
    private final JwtConfiguration jwtConfiguration;

    public NimbusJwtReader(JWSVerifier verifier, JWSAlgorithm algorithm, JwtConfiguration jwtConfiguration, Clock clock)
    {
        this.verifier = verifier;
        this.algorithm = algorithm;
        this.jwtConfiguration = jwtConfiguration;
        this.clock = clock;
    }

    @Override
    public Jwt verify(String jwt, Map<String, JwtClaimVerifier> requiredClaims) throws JwtParseException, JwtVerificationException
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

        if (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime() > jwtConfiguration.getMaxJwtLifetime())
        {
            throw new JwtInvalidClaimException("The difference between 'exp' and 'iat' must be less than " +
                    jwtConfiguration.getMaxJwtLifetime() + ".");
        }

        Date now = clock.now();

        if (claims.getExpirationTime().before(now))
        {
            throw new JwtExpiredException(claims.getExpirationTime(), now);
        }

        for (Map.Entry<String, JwtClaimVerifier> requiredClaim : requiredClaims.entrySet())
        {
            requiredClaim.getValue().verify(claims.getClaim(requiredClaim.getKey()));
        }

        Object querySignatureClaim = claims.getClaim(JwtConstants.Claims.QUERY_SIGNATURE);
        String querySignature = null == querySignatureClaim ? null : querySignatureClaim.toString();
        return new SimpleJwt(claims.getIssuer(), claims.getSubject(), querySignature, jsonPayload.toString());
    }

    @Override
    public JwtClaimVerifier createSignedClaimVerifier(final String signingInput, String claimName)
    {
        return new NimbusJwtClaimSignatureVerifier(verifier, algorithm, signingInput, claimName);
    }
}
