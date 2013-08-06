package com.atlassian.auth.jwt.serviceprovider;

import com.atlassian.auth.jwt.core.*;
import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.ExpiredJwtException;
import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.JwtParseException;
import com.atlassian.auth.jwt.core.com.atlassian.auth.jwt.core.except.JwtSignatureMismatchException;
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
    public static final String JWT_PARAM_NAME = "jwt";

    private final JwtReader jwtReader;

    public JwtAuthenticator(JwtReader jwtReader)
    {
        this.jwtReader = jwtReader;
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

    private Result authenticateJwt(HttpServletRequest request, HttpServletResponse response)
    {
        try
        {
            String jsonString = jwtReader.jwtToJson(request.getParameter(JWT_PARAM_NAME));
            return new Result.Success(new Message()
            {
                @Override
                public String getKey()
                {
                    return null;
                }

                @Override
                public Serializable[] getArguments()
                {
                    return null;
                }
            }, new Principal()
            {
                @Override
                public String getName()
                {
                    return "foo";
                }
            });
        }
        catch (JwtParseException e)
        {
            e.printStackTrace();
        }
        catch (JwtSignatureMismatchException e)
        {
            e.printStackTrace();
        }
        catch (ExpiredJwtException e)
        {
            e.printStackTrace();
        }

        return null;
    }

    private boolean containsJwt(HttpServletRequest request)
    {
        return !StringUtils.isEmpty(request.getParameter(JWT_PARAM_NAME));
    }
}
