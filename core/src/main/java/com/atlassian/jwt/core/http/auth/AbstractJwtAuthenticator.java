package com.atlassian.jwt.core.http.auth;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Map;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.core.http.JwtRequestExtractor;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.exception.JwtUserRejectedException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.httpclient.CanonicalRequestUtil;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import static com.google.common.base.Preconditions.checkNotNull;

public abstract class AbstractJwtAuthenticator<REQ, RES, S> implements JwtAuthenticator<REQ, RES, S>
{
    private static final String BAD_CREDENTIALS_MESSAGE = "Your presented credentials do not provide access to this resource."; // protect against phishing by not saying whether the add-on, user or secret was wrong
    private static final Logger log = LoggerFactory.getLogger(AbstractJwtAuthenticator.class);

    private final JwtRequestExtractor<REQ> jwtExtractor;
    private final AuthenticationResultHandler<RES, S> authenticationResultHandler;

    public AbstractJwtAuthenticator(JwtRequestExtractor<REQ> jwtExtractor,
                                    AuthenticationResultHandler<RES, S> authenticationResultHandler)
    {
        this.jwtExtractor = checkNotNull(jwtExtractor);
        this.authenticationResultHandler = checkNotNull(authenticationResultHandler);
    }

    // cause we can't include anything useful like guava wo getting into OSGI hell
    private static <T> T checkNotNull(T reference) {
        if (reference == null) {
            throw new NullPointerException();
        }
        return reference;
    }

    /**
     * Authenticate the incoming request, returning the status if possible.
     * On bad input or internal failure return a non-success status and return a non-success HTTP response code to
     * {@code response}.
     * Response codes match OAuth:
     * parse error / garbled --> 400 bad request
     * good syntax but purposefully rejected --> 401 unauthorised
     * failure to compute a result --> 500 internal server error
     * rate limiting (not handled here) --> 503 service unavailable
     * default --> 403 forbidden
     *
     * @param request  {@link javax.servlet.http.HttpServletRequest} to be vetted
     * @param response {@link javax.servlet.http.HttpServletResponse} to be send error code if and only if the authentication is unsuccessful
     * @return {@link S} representing the success, failure or error of the authentication attempt
     */
    @Override
    public S authenticate(REQ request, RES response)
    {
        try
        {
            String jwtString = jwtExtractor.extractJwt(request);

            if (null == jwtString)
            {
                throw new IllegalArgumentException("This Authenticator works only with requests containing JWTs");
            }

            Jwt authenticatedJwt = verifyJwt(jwtString, request);
            Principal principal = authenticate(request, authenticatedJwt);
            return authenticationResultHandler.success("Authentication successful!", principal, authenticatedJwt);
        }
        // TODO: Will need to add this to the sal version
//        catch (TypeNotInstalledException e)
//        {
//            return createAndSendInternalError(e, response);
//        }
        catch (IllegalArgumentException e)
        {
            return createAndSendInternalError(e, response);
        }
        catch (IOException e)
        {
            return createAndSendInternalError(e, response);
        }
        catch (NoSuchAlgorithmException e)
        {
            return createAndSendInternalError(e, response);
        }
        catch (JwtParseException e)
        {
            // JWT parse exceptions are going to be seen mainly by add-on vendors during development and say things like "invalid character at index 123" or "foo should be a string"
            return authenticationResultHandler.createAndSendBadRequestError(e, response, getBriefMessageFromException(e));
        }
        catch (JwtVerificationException e)
        {
            // the exception will contain technical details such as "it is expired" or "claim xyz is invalid"
            return authenticationResultHandler.createAndSendUnauthorisedFailure(e, response, getBriefMessageFromException(e));
        }
        catch (JwtIssuerLacksSharedSecretException e)
        {
            return authenticationResultHandler.createAndSendUnauthorisedFailure(e, response, BAD_CREDENTIALS_MESSAGE);
        }
        catch (JwtUnknownIssuerException e)
        {
            return authenticationResultHandler.createAndSendUnauthorisedFailure(e, response, BAD_CREDENTIALS_MESSAGE);
        }
        catch (JwtUserRejectedException e)
        {
            return authenticationResultHandler.createAndSendUnauthorisedFailure(e, response, BAD_CREDENTIALS_MESSAGE);
        }
        catch (Exception e)
        {
            return authenticationResultHandler.createAndSendForbiddenError(e, response);
        }
    }

    protected abstract Jwt verifyJwt(String jwt, Map<String, ? extends JwtClaimVerifier> claimVerifiers)
            throws JwtParseException, JwtVerificationException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException;

    protected abstract Principal authenticate(REQ request, Jwt jwt) throws JwtUserRejectedException;

    private static String getBriefMessageFromException(Exception e)
    {
        return e.getLocalizedMessage() + (null == e.getCause() ? "" : " (caused by " + e.getCause().getLocalizedMessage() + ")");
    }

    private Jwt verifyJwt(String jwtString, REQ request) throws JwtParseException, JwtVerificationException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException
    {
        CanonicalHttpRequest canonicalHttpRequest = jwtExtractor.getCanonicalHttpRequest(request);
        log.debug("Canonical request is: " + CanonicalRequestUtil.toVerboseString(canonicalHttpRequest));
        return verifyJwt(jwtString, JwtClaimVerifiersBuilder.build(canonicalHttpRequest));
    }

    private S createAndSendInternalError(Exception e, RES response)
    {
        return authenticationResultHandler.createAndSendInternalError(e, response, "An internal error occurred. Please check the host product's logs.");
    }

}
