package com.atlassian.jwt.plugin.sal;

import com.atlassian.applinks.api.TypeNotInstalledException;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.jwt.core.JwtUtil;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.httpclient.CanonicalHttpServletRequest;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;

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
                request.setAttribute(ADD_ON_ID_ATTRIBUTE, jwt.getIssuer());
                return new Result.Success(createMessage("Authentication successful!"), userPrincipal);
            }
            else
            {
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
        catch (IllegalArgumentException e)
        {
            return createFailure(e);
        }
        catch (IOException e)
        {
            return createError(e);
        }
        catch (NoSuchAlgorithmException e)
        {
            return createError(e);
        }
    }

    private Jwt verifyJwt(String jwtString, HttpServletRequest request) throws JwtParseException, JwtVerificationException, TypeNotInstalledException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException
    {
        return jwtService.verifyJwt(jwtString, JwtClaimVerifiersBuilder.build(new CanonicalHttpServletRequest(request))).getJwt();
    }

    private static Result.Error createError(Exception e)
    {
        e.printStackTrace(System.out);
        return createError(e.getLocalizedMessage());
    }

    private static Result.Error createError(String message)
    {
        return new Result.Error(createMessage(message));
    }

    private static Result.Failure createFailure(Exception e)
    {
        e.printStackTrace(System.out);
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
