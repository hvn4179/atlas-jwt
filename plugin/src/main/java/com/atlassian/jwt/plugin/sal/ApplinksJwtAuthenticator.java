package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.core.http.auth.SimplePrincipal;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Map;
import static com.atlassian.jwt.JwtConstants.HttpRequests.ADD_ON_ID_ATTRIBUTE_NAME;

/**
 * A JwtAuthenticator for requests associated with an ApplicationLink (i.e. for requests between two linked applications)
 */
public class ApplinksJwtAuthenticator extends AbstractJwtAuthenticator<HttpServletRequest, HttpServletResponse, Authenticator.Result>
        implements Authenticator
{
    private final JwtService jwtService;
    private final AuthenticationController authenticationController;

    public ApplinksJwtAuthenticator(JwtService jwtService, AuthenticationController authenticationController)
    {
        super(new JavaxJwtRequestExtractor(), new ApplinksAuthenticationResultHandler());
        this.jwtService = jwtService;
        this.authenticationController = authenticationController;
    }

    @Override
    protected Principal authenticate(HttpServletRequest request, Jwt jwt) throws JwtUserRejectedException
    {
        Principal userPrincipal = new SimplePrincipal(jwt.getSubject()); // TODO: ACDEV-653: principal should be looked up internally from the issuer id

        if (!authenticationController.canLogin(userPrincipal, request))
        {
            throw new JwtUserRejectedException(String.format("User [%s] and request [%s] are not a valid login combination", userPrincipal.getName(), request));
        }

        request.setAttribute(ADD_ON_ID_ATTRIBUTE_NAME, jwt.getIssuer());
        return userPrincipal;
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
            // TODO: Peter: TypeNotInstalledException is in applinks which the base class can't depend on.
            // This is the best I could come up with. Thoughts?
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

}
