package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.UnverifiedJwt;
import com.atlassian.jwt.core.JwtConfiguration;
import com.atlassian.jwt.core.SystemPropertyJwtConfiguration;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtReader;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.reader.UnverifiedJwtReader;

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
    public JwtReader macVerifyingReader(String sharedSecret)
    {
        return new NimbusMacJwtReader(sharedSecret, jwtConfiguration);
    }

    @Override
    public JwtReader getReader(String jwt) throws JwtParseException, JwsUnsupportedAlgorithmException, JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        UnverifiedJwt unverifiedJwt = new NimbusUnverifiedJwtReader().parse(jwt);
        SigningAlgorithm algorithm = validateAlgorithm(unverifiedJwt);
        String issuer = validateIssuer(unverifiedJwt);

        if (algorithm.requiresSharedSecret())
        {
            return macVerifyingReader(jwtIssuerSharedSecretService.getSharedSecret(issuer));
        }

        throw new JwsUnsupportedAlgorithmException(String.format("Currently we support only symmetric signing algorithms such as %s, and not %s. Try a symmetric algorithm.", SigningAlgorithm.HS256, algorithm.name()));
    }

    private String validateIssuer(UnverifiedJwt unverifiedJwt) throws JwtUnknownIssuerException
    {
        String issuer = unverifiedJwt.getIssuer();

        if (!jwtIssuerValidator.isValid(issuer))
        {
            throw new JwtUnknownIssuerException(issuer);
        }

        return issuer;
    }

    private SigningAlgorithm validateAlgorithm(UnverifiedJwt unverifiedJwt) throws JwsUnsupportedAlgorithmException
    {
        return SigningAlgorithm.forName(unverifiedJwt.getAlgorithm());
    }
}
