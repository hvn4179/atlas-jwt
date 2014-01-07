package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.core.http.auth.SimplePrincipal;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.httpclient.CanonicalHttpServletRequest;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Map;

// TODO: Peter should we rename this to something like ApplinksJwtAuthenticator? I added an interface by the same name so one of them needs renaming
public class JwtAuthenticator extends AbstractJwtAuthenticator<HttpServletRequest, HttpServletResponse, Authenticator.Result>
        implements Authenticator
{
    private final JwtService jwtService;
    private final AuthenticationController authenticationController;

    private static final String BAD_CREDENTIALS_MESSAGE = "Your presented credentials do not provide access to this resource."; // protect against phishing by not saying whether the add-on, user or secret was wrong
    private static final String ADD_ON_ID_ATTRIBUTE = "Plugin-Key"; // TODO: extract out of here and Connect's ApiScopingFilter into a lib referenced by both
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticator.class);

    public JwtAuthenticator(JwtService jwtService, AuthenticationController authenticationController)
    {
        super(new JavaxJwtRequestExtractor(), new JavaxAuthenticationResultHandler());
        this.jwtService = jwtService;
        this.authenticationController = authenticationController;
    }

    @Override
    protected Principal authenticate(HttpServletRequest request, Jwt jwt) throws JwtUserRejectedException
    {
        Principal userPrincipal = new SimplePrincipal(jwt.getSubject()); // TODO: ACDEV-653: principal should be looked up interally from the issuer id

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
