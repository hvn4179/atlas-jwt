package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.exception.*;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
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
            Jwt jwt = verifyJwt(jwtString, request);
            Principal userPrincipal = new SimplePrincipal(jwt.getSubject());

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
        catch (JwtIssuerLacksSharedSecretException e)
        {
            return createFailure(e);
        }
        catch (JwtUnknownIssuerException e)
        {
            return createFailure(e);
        }
        catch (IOException e)
        {
            return createError(e);
        }
    }

    private Jwt verifyJwt(String jwtString, HttpServletRequest request) throws JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException
    {
        Jwt jwt = jwtService.verifyJwt(jwtString).getJwt();
        verifyQuerySignature(jwt, request);
        return jwt;
    }

    private void verifyQuerySignature(Jwt jwt, HttpServletRequest request) throws JwtSignatureMismatchException, IOException, TypeNotInstalledException
    {
        String receivedSignature = jwt.getQuerySignature();

        if (null == receivedSignature)
        {
            throw new JwtSignatureMismatchException(String.format("JWT must include a '%s' claim; please specify one", JwtConstants.Claims.QUERY_SIGNATURE));
        }

        if ("".equals(receivedSignature))
        {
            throw new JwtSignatureMismatchException(String.format("JWT must included a non-empty-string '%s' claim; please specify one", JwtConstants.Claims.QUERY_SIGNATURE));
        }

        String computedSignature = jwtService.issueSignature(JwtUtil.canonicalizeQuery(request), jwtService.getApplicationLink(jwt));

        if (!receivedSignature.equals(computedSignature))
        {
            throw new JwtSignatureMismatchException(String.format("Received signature '%s' does not match computed signature '%s'", receivedSignature, computedSignature));
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

            @Override
            public String toString()
            {
                return message;
            }
        };
    }
}
