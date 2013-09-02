package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.Jwt;
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

    /**
     * A {@link com.atlassian.jwt.Jwt} that has not yet been verified. The {@link #getJsonPayload() payload} should not be trusted.
     *
     * @since 1.0
     */
    private static interface UnverifiedJwt extends Jwt
    {
        /**
         * @return the raw algorithm specified in the JWT header.
         */
        String getAlgorithm();
    }

    private static class SimpleUnverifiedJwt extends SimpleJwt implements UnverifiedJwt
    {
        private final String algorithm;

        public SimpleUnverifiedJwt(String algorithm, String iss, String sub, String payload)
        {
            super(iss, sub, payload);
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Parses {@link UnverifiedJwt JWTs} from incoming requests <strong>without attempting verification</strong>.
     * <p/>
     * An unverified reader should only be used to look up the credentials required to verify a particular JWT.
     * <p/>
     * Other data associated with {@link UnverifiedJwt unverified JWTs} must not be trusted. Use {@link JwtReader} instead.
     *
     * @since 1.0
     */
    private static interface UnverifiedJwtReader
    {
        /**
         * @param jwt an JSON Web Token, (see <a href="http://tools.ietf.org/html/draft-jones-json-web-token-10#section-3.1">example</a>)
         * @return an <strong>unverified</strong> {@link UnverifiedJwt JWT}. <strong>DO NOT</strong> trust
         *         values associated with this JWT. Use a {@link JwtReader verifying JwtReader} instead.
         * @throws JwtParseException if the JWT string was malformed
         */
        UnverifiedJwt parse(String jwt) throws JwtParseException;
    }

    private static class NimbusUnverifiedJwtReader implements UnverifiedJwtReader
    {
        public UnverifiedJwt parse(String jwt) throws JwtParseException
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
