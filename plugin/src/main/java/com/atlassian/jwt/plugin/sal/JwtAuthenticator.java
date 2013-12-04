package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.exception.*;
import com.atlassian.jwt.httpclient.CanonicalHttpServletRequest;
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

public class JwtAuthenticator implements Authenticator
{
    private final JwtService jwtService;
    private final AuthenticationController authenticationController;

    private static final String ADD_ON_ID_ATTRIBUTE = "Plugin-Key"; // TODO: extract out of here and Connect's ApiScopingFilter into a lib referenced by both
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticator.class);

    public JwtAuthenticator(JwtService jwtService, AuthenticationController authenticationController)
    {
        this.jwtService = jwtService;
        this.authenticationController = authenticationController;
    }

    /**
     * Authenticate the incoming request, returning {@link Result.Success} if possible.
     * On bad input or internal failure return a non-success {@link Result} and return a non-success HTTP response code to {@code response}.
     * Response codes match OAuth:
     *   parse error / garbled --> 400 bad request
     *   good syntax but purposefully rejected --> 401 unauthorised
     *   user / issuer refused --> 503 service unavailable
     *   failure to compute a result --> 500 internal server error
     *   default --> 403 forbidden
     * @param request {@link HttpServletRequest} to be vetted
     * @param response {@link HttpServletResponse} to be send error code if and only if the authentication is unsuccessful
     * @return {@link Result} representing the success, failure or error of the authentication attempt
     */
    @Override
    public Result authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        try
        {
            String jwt = JwtUtil.extractJwt(request);

            if (null == jwt)
            {
                throw new IllegalArgumentException("This Authenticator works only with requests containing JWTs");
            }

            return new Result.Success(createMessage("Authentication successful!"), authenticate(request, jwt));
        }
        catch (TypeNotInstalledException e)
        {
            return createAndSendInternalError(e, response);
        }
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
            return createAndSendBadRequestError(e, response, getBriefMessageFromException(e));
        }
        catch (JwtVerificationException e)
        {
            // the exception will contain technical details such as "it is expired" or "claim xyz is invalid"
            return createAndSendUnauthorisedFailure(e, response, getBriefMessageFromException(e));
        }
        catch (JwtIssuerLacksSharedSecretException e)
        {
            return createAndSendServiceUnavilableFailure(e, response);
        }
        catch (JwtUnknownIssuerException e)
        {
            return createAndSendServiceUnavilableFailure(e, response);
        }
        catch (JwtUserRejectedException e)
        {
            return createAndSendServiceUnavilableFailure(e, response);
        }
        catch (Exception e)
        {
            return createAndSendForbiddenError(e, response);
        }
    }

    private static String getBriefMessageFromException(Exception e)
    {
        return e.getLocalizedMessage() + (null == e.getCause() ? "" : " (caused by " + e.getCause().getLocalizedMessage() + ")");
    }

    private Principal authenticate(final HttpServletRequest request, String jwtString) throws NoSuchAlgorithmException, TypeNotInstalledException, IOException, JwtIssuerLacksSharedSecretException, JwtParseException, JwtVerificationException, JwtUnknownIssuerException, JwtUserRejectedException
    {
        Jwt jwt = verifyJwt(jwtString, request);
        Principal userPrincipal = new SimplePrincipal(jwt.getSubject()); // TODO: ACDEV-653: principal should be looked up interally from the issuer id

        if (!authenticationController.canLogin(userPrincipal, request))
        {
            throw new JwtUserRejectedException(String.format("User [%s] and request [%s] are not a valid login combination", userPrincipal.getName(), request));
        }

        request.setAttribute(ADD_ON_ID_ATTRIBUTE, jwt.getIssuer());
        return userPrincipal;
    }

    private Jwt verifyJwt(String jwtString, HttpServletRequest request) throws JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException
    {
        return jwtService.verifyJwt(jwtString, JwtClaimVerifiersBuilder.build(new CanonicalHttpServletRequest(request))).getJwt();
    }

    private Result createAndSendInternalError(Exception e, HttpServletResponse response)
    {
        // the internal error could give away runtime details that could be useful in an attack, so don't display it externally
        return createAndSendError(e, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An internal error occurred. Please check the host product's logs.");
    }

    private Result createAndSendBadRequestError(Exception e, HttpServletResponse response, String externallyVisibleMessage)
    {
        // the message will probably be seen by add-on vendors during add-on development
        return createAndSendError(e, response, HttpServletResponse.SC_BAD_REQUEST, externallyVisibleMessage);
    }

    private Result createAndSendUnauthorisedFailure(Exception e, HttpServletResponse response, String externallyVisibleMessage)
    {
        // the jwt has good syntax but was rejected, and was not rejected due to the user or issuer specifically
        return createAndSendFailure(e, response, HttpServletResponse.SC_UNAUTHORIZED, externallyVisibleMessage);
    }

    private Result createAndSendServiceUnavilableFailure(Exception e, HttpServletResponse response)
    {
        // the user and/or add-on was specifically rejected, so be a little mysterious in the message
        return createAndSendFailure(e, response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service unavailable. Please contact the system administrator if you believe that this is in error.");
    }

    private Result createAndSendForbiddenError(Exception e, HttpServletResponse response)
    {
        // this is the default error response, so the message is quite general
        return createAndSendError(e, response, HttpServletResponse.SC_FORBIDDEN, "Access to this resource is forbidden without successful authentication. Please supply valid credentials.");
    }

    private static Result.Error createAndSendError(Exception e, HttpServletResponse response, int httpResponseCode, String externallyVisibleMessage)
    {
        log.debug("Error during JWT authentication: ", e);
        sendErrorResponse(response, httpResponseCode, externallyVisibleMessage);
        return new Result.Error(createMessage(e.getLocalizedMessage()));
    }

    private static Result.Failure createAndSendFailure(Exception e, HttpServletResponse response, int httpResponseCode, String externallyVisibleMessage)
    {
        log.debug("Failure during JWT authentication: ", e);
        sendErrorResponse(response, httpResponseCode, externallyVisibleMessage);
        return new Result.Failure(createMessage(e.getLocalizedMessage()));
    }

    private static void sendErrorResponse(HttpServletResponse response, int httpResponseCode, String externallyVisibleMessage)
    {
        response.reset();

        try
        {
            response.sendError(httpResponseCode, externallyVisibleMessage);
        }
        catch (IOException doubleFacePalm)
        {
            log.error("Encountered IOException while trying to report an authentication failure.", doubleFacePalm);
            doubleFacePalm.printStackTrace();
            response.reset();
            response.setStatus(httpResponseCode); // no error message, but hopefully the response code will still be useful
        }
    }

    private static Message createMessage(final String message)
    {
        return new Message()
        {
            @Override
            public String getKey()
            {
                return message;
            }

            @Override
            public Serializable[] getArguments()
            {
                return null;
            }

            @Override
            public String toString()
            {
                return message;
            }
        };
    }
}
