package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.JwtConfiguration;
import com.atlassian.jwt.core.SimpleJwt;
import com.atlassian.jwt.core.SystemPropertyJwtConfiguration;
import com.atlassian.jwt.exception.JwsUnsupportedAlgorithmException;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;

public class NimbusJwtReaderFactory implements JwtReaderFactory
{
    private final JwtConfiguration jwtConfiguration;
    private final JwtIssuerValidator jwtIssuerValidator;
    private final JwtIssuerSharedSecretService jwtIssuerSharedSecretService;

    public NimbusJwtReaderFactory(JwtIssuerValidator jwtIssuerValidator, JwtIssuerSharedSecretService jwtIssuerSharedSecretService)
    {
        this(new SystemPropertyJwtConfiguration(), jwtIssuerValidator, jwtIssuerSharedSecretService);
    }

    public NimbusJwtReaderFactory(JwtConfiguration jwtConfiguration, JwtIssuerValidator jwtIssuerValidator, JwtIssuerSharedSecretService jwtIssuerSharedSecretService)
    {
        this.jwtConfiguration = jwtConfiguration;
        this.jwtIssuerValidator = jwtIssuerValidator;
        this.jwtIssuerSharedSecretService = jwtIssuerSharedSecretService;
    }

    @Override
    public JwtReader getReader(String jwt) throws JwtParseException, JwsUnsupportedAlgorithmException, JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        SimpleUnverifiedJwt unverifiedJwt = new NimbusUnverifiedJwtReader().parse(jwt);
        SigningAlgorithm algorithm = validateAlgorithm(unverifiedJwt);
        String issuer = validateIssuer(unverifiedJwt);

        if (algorithm.requiresSharedSecret())
        {
            return macVerifyingReader(jwtIssuerSharedSecretService.getSharedSecret(issuer));
        }

        throw new JwsUnsupportedAlgorithmException(String.format("Currently we support only symmetric signing algorithms such as %s, and not %s. Try a symmetric algorithm.", SigningAlgorithm.HS256, algorithm.name()));
    }

    private JwtReader macVerifyingReader(String sharedSecret)
    {
        return new NimbusMacJwtReader(sharedSecret, jwtConfiguration);
    }

    private String validateIssuer(SimpleUnverifiedJwt unverifiedJwt) throws JwtUnknownIssuerException
    {
        String issuer = unverifiedJwt.getIssuer();

        if (!jwtIssuerValidator.isValid(issuer))
        {
            throw new JwtUnknownIssuerException(issuer);
        }

        return issuer;
    }

    private SigningAlgorithm validateAlgorithm(SimpleUnverifiedJwt unverifiedJwt) throws JwsUnsupportedAlgorithmException
    {
        return SigningAlgorithm.forName(unverifiedJwt.getAlgorithm());
    }

    private static class SimpleUnverifiedJwt extends SimpleJwt
    {
        private final String algorithm;

        public SimpleUnverifiedJwt(String algorithm, String iss, String sub, String payload)
        {
            super(iss, sub, payload);
            this.algorithm = algorithm;
        }

        public String getAlgorithm()
        {
            return algorithm;
        }
    }

    private static class NimbusUnverifiedJwtReader
    {
        public SimpleUnverifiedJwt parse(String jwt) throws JwtParseException
        {
            JWSObject jwsObject = parseJWSObject(jwt);
            try
            {
                JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
                return new SimpleUnverifiedJwt(jwsObject.getHeader().getAlgorithm().getName(), claims.getIssuer(), claims.getSubject(), jwsObject.getPayload().toString());
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
}
