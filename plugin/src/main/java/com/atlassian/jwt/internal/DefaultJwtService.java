package com.atlassian.jwt.internal;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtService;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.jwt.writer.JwtWriterFactory;

import javax.annotation.Nonnull;
import java.util.Map;

public class DefaultJwtService implements JwtService
{
    private final JwtReaderFactory jwtReaderFactory;
    private final JwtWriterFactory jwtWriterFactory;

    public DefaultJwtService(JwtReaderFactory jwtReaderFactory, JwtWriterFactory jwtWriterFactory)
    {
        this.jwtReaderFactory = jwtReaderFactory;
        this.jwtWriterFactory = jwtWriterFactory;
    }

    @Nonnull
    @Override
    public String issueJwt(@Nonnull String jsonPayload, @Nonnull String sharedSecret)
    {
        return jwtWriterFactory.macSigningWriter(SigningAlgorithm.HS256, sharedSecret)
                .jsonToJwt(jsonPayload);
    }

    @Nonnull
    @Override
    public Jwt verifyJwt(@Nonnull String jwt, @Nonnull Map<String, ? extends JwtClaimVerifier> claimVerifiers) throws JwtIssuerLacksSharedSecretException, JwtParseException, JwtUnknownIssuerException, JwtVerificationException
    {
        return jwtReaderFactory.getReader(jwt).readAndVerify(jwt, claimVerifiers);
    }
}
