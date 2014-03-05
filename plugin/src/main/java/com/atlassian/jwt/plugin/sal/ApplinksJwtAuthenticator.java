package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.core.http.auth.SimplePrincipal;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.sal.api.auth.Authenticator;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Map;

import static com.atlassian.jwt.JwtConstants.HttpRequests.ADD_ON_ID_ATTRIBUTE_NAME;
import static java.lang.Boolean.getBoolean;

/**
 * A JwtAuthenticator for requests associated with an ApplicationLink (i.e. for requests between two linked applications)
 */
public class ApplinksJwtAuthenticator extends AbstractJwtAuthenticator<HttpServletRequest, HttpServletResponse, Authenticator.Result>
        implements Authenticator
{
    private final JwtService jwtService;
    private final JwtApplinkFinder jwtApplinkFinder;
    private final CrowdService crowdService;

    private static final Logger LOG = LoggerFactory.getLogger(ApplinksJwtAuthenticator.class);

    public ApplinksJwtAuthenticator(JwtService jwtService, JwtApplinkFinder jwtApplinkFinder, CrowdService crowdService)
    {
        super(new JavaxJwtRequestExtractor(), new ApplinksAuthenticationResultHandler());
        this.jwtService = checkNotNull(jwtService);
        this.jwtApplinkFinder = checkNotNull(jwtApplinkFinder);
        this.crowdService = checkNotNull(crowdService);
    }

    @Override
    protected Principal authenticate(HttpServletRequest request, Jwt jwt) throws JwtUserRejectedException
    {
        Principal principal;
        String subject = jwt.getSubject();
        if (allowImpersonation())
        {
            principal = (subject == null || subject.length() == 0) ? null : new SimplePrincipal(subject);
        }
        else
        {
            if (null != subject)
            {
                LOG.warn(String.format("Ignoring subject claim '%s' on incoming request '%s' from JWT issuer '%s'", subject, request.getRequestURI(), jwt.getIssuer()));
            }
            principal = getPrincipalFromApplink(jwt.getIssuer(), request);
        }
        request.setAttribute(ADD_ON_ID_ATTRIBUTE_NAME, jwt.getIssuer());
        return principal;
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

    private Principal getPrincipalFromApplink(String jwtIssuer, HttpServletRequest request) throws JwtUserRejectedException
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
                String userKeyString = (String) addOnUserKey;
                User user = crowdService.getUser(userKeyString);

                // if the add-on's user has been disabled then we explicitly deny access so that admins and our add-on
                // lifecycle code can instantly prevent an add-on from making any calls (e.g. when an add-on is disabled)
                if (null == user)
                {
                    throw new JwtUserRejectedException(String.format("The user '%s' does not exist", userKeyString));
                }
                else if (!user.isActive())
                {
                    throw new JwtUserRejectedException(String.format("The user '%s' is inactive", userKeyString));
                }

                userPrincipal = new SimplePrincipal(userKeyString);
            }
            else
            {
                throw new IllegalStateException(String.format("ApplicationLink '%s' for JWT issuer '%s' has the non-String user key '%s'. The user key must be a String: please correct it by editing the database or, if the issuer is a Connect add-on, by re-installing it.",
                        applicationLink.getId(), jwtIssuer, addOnUserKey));
            }
        }

        return userPrincipal;
    }

    public boolean allowImpersonation()
    {
        return getBoolean(JwtConstants.AppLinks.SYS_PROP_ALLOW_IMPERSONATION);
    }
}
