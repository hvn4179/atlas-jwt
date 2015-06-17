package com.atlassian.jwt.internal.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.sal.api.auth.Authenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static com.atlassian.jwt.JwtConstants.HttpRequests.ADD_ON_ID_ATTRIBUTE_NAME;
import static com.atlassian.jwt.JwtConstants.HttpRequests.JWT_SUBJECT_ATTRIBUTE_NAME;

/**
 * A JwtAuthenticator for requests associated with an ApplicationLink (i.e. for requests between two linked applications)
 */
public class JwtAuthenticatorImpl extends AbstractJwtAuthenticator<HttpServletRequest, HttpServletResponse, Authenticator.Result>
        implements Authenticator
{
    private final JwtService jwtService;

    public JwtAuthenticatorImpl(JwtService jwtService)
    {
        super(new JavaxJwtRequestExtractor(), new DefaultAuthenticationResultHandler());
        this.jwtService = checkNotNull(jwtService);
    }

    @Override
    protected void tagRequest(HttpServletRequest request, Jwt jwt) throws JwtUserRejectedException
    {
        request.setAttribute(ADD_ON_ID_ATTRIBUTE_NAME, jwt.getIssuer());
        request.setAttribute(JWT_SUBJECT_ATTRIBUTE_NAME, jwt.getSubject());
    }

    @Override
    protected Jwt verifyJwt(String jwt, Map<String, ? extends JwtClaimVerifier> claimVerifiers) throws JwtParseException, JwtVerificationException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException
    {
        try
        {
            return jwtService.verifyJwt(jwt, claimVerifiers).getJwt();
        }
        catch (TypeNotInstalledException e)
        {
            // TypeNotInstalledException is in applinks which the base class can't depend on.
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}
