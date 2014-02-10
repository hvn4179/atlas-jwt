package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.core.http.auth.SimplePrincipal;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private final JwtApplinkFinder jwtApplinkFinder;

    private static final Logger LOG = LoggerFactory.getLogger(ApplinksJwtAuthenticator.class);

    public ApplinksJwtAuthenticator(JwtService jwtService, AuthenticationController authenticationController, JwtApplinkFinder jwtApplinkFinder)
    {
        super(new JavaxJwtRequestExtractor(), new ApplinksAuthenticationResultHandler());
        this.jwtService = checkNotNull(jwtService);
        this.authenticationController = checkNotNull(authenticationController);
        this.jwtApplinkFinder = checkNotNull(jwtApplinkFinder);
    }

    @Override
    protected Principal authenticate(HttpServletRequest request, Jwt jwt) throws JwtUserRejectedException
    {
        if (null != jwt.getSubject())
        {
            LOG.warn(String.format("Ignoring subject claim '%s' on incoming request '%s' from JWT issuer '%s'", jwt.getSubject(), request.getRequestURI(), jwt.getIssuer()));
        }

        request.setAttribute(ADD_ON_ID_ATTRIBUTE_NAME, jwt.getIssuer());
        return getPrincipal(jwt.getIssuer(), request);
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
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private Principal getPrincipal(String jwtIssuer, HttpServletRequest request) throws JwtUserRejectedException
    {
        Principal userPrincipal = null; // default to being able to see only public resources

        ApplicationLink applicationLink = jwtApplinkFinder.find(jwtIssuer);
        Object addOnUserKey = applicationLink.getProperty(JwtConstants.AppLinks.ADD_ON_USER_KEY_PROPERTY_NAME);

        if (null == addOnUserKey)
        {
            LOG.warn(String.format("Application link '%s' for JWT issuer '%s' has no '%s' property. Incoming requests from this issuer will be authenticated as an anonymous request.",
                    applicationLink.getId(), jwtIssuer, JwtConstants.AppLinks.ADD_ON_USER_KEY_PROPERTY_NAME));
        }
        else
        {
            if (addOnUserKey instanceof String)
            {
                userPrincipal = new SimplePrincipal((String)addOnUserKey);

                // if the add-on's user has been disabled then we explicitly deny access so that admins and our add-on
                // lifecycle code can instantly prevent an add-on from making any calls (e.g. when an add-on is disabled)
                if (!authenticationController.canLogin(userPrincipal, request))
                {
                    throw new JwtUserRejectedException(String.format("The user '%s' is disabled or does not exist", addOnUserKey));
                }
            }
            else
            {
                throw new IllegalStateException(String.format("ApplicationLink '%s' for JWT issuer '%s' has the non-String user key '%s'. The user key must be a String: please correct it by editing the database or, if the issuer is a Connect add-on, by re-installing it.",
                        applicationLink.getId(), jwtIssuer, addOnUserKey));
            }
        }

        return userPrincipal;
    }
}
