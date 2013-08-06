package com.atlassian.auth.jwt.serviceprovider;

import com.atlassian.auth.jwt.core.JwtIssuerToAccountNameMapper;
import com.atlassian.auth.jwt.core.JwtReader;
import com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.security.Principal;

/**
 * Author: pbrownlow
 * Date: 5/08/13
 * Time: 11:50 AM
 */
public class JwtAuthenticator implements Authenticator
{
    private final JwtReader jwtReader;
    private final JwtIssuerToAccountNameMapper issuerToAccountNameMapper;
    private final AuthenticationController authenticationController;

    public JwtAuthenticator(JwtReader jwtReader, JwtIssuerToAccountNameMapper issuerToAccountNameMapper, AuthenticationController authenticationController)
    {
        this.jwtReader = jwtReader;
        this.issuerToAccountNameMapper = issuerToAccountNameMapper;
        this.authenticationController = authenticationController;
    }

    @Override
    public Result authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        if (JwtUtils.requestContainsJwt(request))
        {
            return authenticateJwt(request, response);
        }

        // TODO: consider localising this error message
        throw new IllegalArgumentException("This Authenticator works only with requests containing JWTs");
    }

    private Result authenticateJwt(final HttpServletRequest request, HttpServletResponse response)
    {
        try
        {
            String jsonString = jwtReader.jwtToJson(request.getParameter(JwtUtils.JWT_PARAM_NAME));
            String jwtIssuer = jwtReader.getIssuer(jsonString);
            final String username = issuerToAccountNameMapper.get(jwtIssuer);
            final Principal userPrincipal = createPrincipal(username);

            if (authenticationController.canLogin(userPrincipal, request))
            {
                return new Result.Success(createMessage("Authentication successful!"), userPrincipal);
            }
            else
            {
                // TODO: consider localising this error message
                return new Result.Failure(createMessage(String.format("User [%s] and request [%s] are not a valid login combination", username, request)));
            }
        }
        catch (JwtParseException e)
        {
            return createError(e);
        }
        catch (JwtSignatureMismatchException e)
        {
            return createFailure(e);
        }
        catch (ExpiredJwtException e)
        {
            return createFailure(e);
        }
    }

    private static Principal createPrincipal(final String username)
    {
        return new Principal()
        {
            @Override
            public String getName()
            {
                return username;
            }
        };
    }

    private static Result.Error createError(Exception e)
    {
        return createError(e.getLocalizedMessage());
    }

    private static Result.Error createError(String message)
    {
        return new Result.Error(createMessage(message));
    }

    private static Result.Failure createFailure(Exception e)
    {
        return createFailure(e.getLocalizedMessage());
    }

    private static Result.Failure createFailure(String message)
    {
        return new Result.Failure(createMessage(message));
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
        };
    }
}
