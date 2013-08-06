package com.atlassian.auth.jwt.serviceprovider;

import com.atlassian.auth.jwt.core.*;
import com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;
import com.atlassian.sal.api.auth.AuthenticationController;
import com.atlassian.sal.api.auth.Authenticator;
import com.atlassian.sal.api.message.Message;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
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
    public static final String JWT_PARAM_NAME = "jwt";

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
        if (containsJwt(request))
        {
            return authenticateJwt(request, response);
        }

        throw new IllegalArgumentException("This Authenticator works only with requests containing JWTs");
    }

    private Result authenticateJwt(final HttpServletRequest request, HttpServletResponse response)
    {
        try
        {
            final String jsonString = jwtReader.jwtToJson(request.getParameter(JWT_PARAM_NAME));
            String jwtIssuer = jwtReader.getIssuer(jsonString);
            final String username = issuerToAccountNameMapper.get(jwtIssuer);
            final Principal userPrincipal = new Principal()
            {
                @Override
                public String getName()
                {
                    return username;
                }
            };

            if (authenticationController.canLogin(userPrincipal, request))
            {
                return new Result.Success(new Message()
                {
                    @Override
                    public String getKey()
                    {
                        return jsonString;
                    }

                    @Override
                    public Serializable[] getArguments()
                    {
                        return null;
                    }
                }, userPrincipal);
            }
            else
            {
                return new Result.Failure(new Message()
                {
                    @Override
                    public String getKey()
                    {
                        return String.format("User [%s] and request [%s] are not a valid login combination", username, request);
                    }

                    @Override
                    public Serializable[] getArguments()
                    {
                        return null;
                    }
                });
            }
        }
        catch (final JwtParseException e)
        {
            return new Result.Error(new Message()
            {
                @Override
                public String getKey()
                {
                    return e.getLocalizedMessage();
                }

                @Override
                public Serializable[] getArguments()
                {
                    return null;
                }
            });
        }
        catch (final JwtSignatureMismatchException e)
        {
            return new Result.Failure(new Message()
            {
                @Override
                public String getKey()
                {
                    return e.getLocalizedMessage();
                }

                @Override
                public Serializable[] getArguments()
                {
                    return null;
                }
            });
        }
        catch (final ExpiredJwtException e)
        {
            return new Result.Failure(new Message()
            {
                @Override
                public String getKey()
                {
                    return e.getLocalizedMessage();
                }

                @Override
                public Serializable[] getArguments()
                {
                    return null;
                }
            });
        }
    }

    private boolean containsJwt(HttpServletRequest request)
    {
        return !StringUtils.isEmpty(request.getParameter(JWT_PARAM_NAME));
    }
}
