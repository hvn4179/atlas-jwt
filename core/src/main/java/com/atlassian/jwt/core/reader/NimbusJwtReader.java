package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.VerifiedJwt;
import com.atlassian.jwt.core.Clock;
import com.atlassian.jwt.core.NimbusUtil;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.core.SystemClock;
import com.atlassian.jwt.exception.ExpiredJwtException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtSignatureMismatchException;
import com.atlassian.jwt.reader.JwtReader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.Date;

public class NimbusJwtReader implements JwtReader
{
    private final JWSVerifier verifier;
    private final Clock clock;
    private final SigningAlgorithm algorithm;

    public NimbusJwtReader(SigningAlgorithm algorithm, JWSVerifier verifier)
    {
        this(algorithm, verifier, SystemClock.getInstance());
    }

    public NimbusJwtReader(SigningAlgorithm algorithm, JWSVerifier verifier, Clock clock)
    {
        this.algorithm = algorithm;
        this.verifier = verifier;
        this.clock = clock;
    }

    @Override
    public VerifiedJwt verify(String jwt) throws JwtParseException, JwtSignatureMismatchException, ExpiredJwtException
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

        if (claims.getExpirationTime() == null) {
            throw new JwtParseException("'exp' is a required claim. Atlassian JWT does not allow JWTs with unlimited lifetimes.");
        }

        Date now = clock.now();

        if (claims.getExpirationTime().before(now))
        {
            throw new ExpiredJwtException(claims.getExpirationTime(), now);
        }

        String prn = NimbusUtil.getStringClaimValue(claims, "prn");

        return new SimpleJwt(claims.getIssuer(), prn, algorithm, jsonPayload.toString());
    }


}
