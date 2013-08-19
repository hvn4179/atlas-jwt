package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.applinks.ApplinkJwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.security.Principal;

public class JwtAuthenticator implements Authenticator
{
    private final JwtService jwtService;
    private final AuthenticationController authenticationController;

    public JwtAuthenticator(JwtService jwtService, AuthenticationController authenticationController)
    {
        this.jwtService = jwtService;
        this.authenticationController = authenticationController;
    }

    @Override
    public Result authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        String jwt = JwtUtil.extractJwt(request);
        if (jwt != null)
        {
            return authenticate(request, jwt);
        }

        // TODO: consider localising this error message
        throw new IllegalArgumentException("This Authenticator works only with requests containing JWTs");
    }

    private Result authenticate(final HttpServletRequest request, String jwtString)
    {
        try
        {
            ApplinkJwt jwt = jwtService.verifyJwt(jwtString);
            Principal userPrincipal = new SimplePrincipal(jwt.getJwt().getPrincipal());

            if (authenticationController.canLogin(userPrincipal, request))
            {
                return new Result.Success(createMessage("Authentication successful!"), userPrincipal);
            }
            else
            {
                // TODO: consider localising this error message
                return new Result.Failure(createMessage(String.format("User [%s] and request [%s] are not a valid login combination", userPrincipal.getName(), request)));
            }
        }
        catch (TypeNotInstalledException e)
        {
            return createError(e);
        }
        catch (JwtParseException e)
        {
            return createError(e);
        }
        catch (JwtVerificationException e)
        {
            return createFailure(e);
        }
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
