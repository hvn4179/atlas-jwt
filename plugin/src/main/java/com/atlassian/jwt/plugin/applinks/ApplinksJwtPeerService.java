package com.atlassian.jwt.plugin.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.CredentialsRequiredException;
import com.atlassian.applinks.api.auth.Anonymous;
import com.atlassian.applinks.host.spi.InternalHostApplication;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.applinks.JwtPeerService;
import com.atlassian.jwt.applinks.exception.JwtRegistrationFailedException;
import com.atlassian.jwt.plugin.security.SecretGenerator;
import com.atlassian.sal.api.net.Request;
import com.atlassian.sal.api.net.Response;
import com.atlassian.sal.api.net.ResponseException;
import com.atlassian.sal.api.net.ResponseHandler;

public class ApplinksJwtPeerService implements JwtPeerService
{

    public static final String ATLASSIAN_JWT_SHARED_SECRET = "atlassian.jwt.shared.secret";

    private final InternalHostApplication hostApplication;

    public ApplinksJwtPeerService(InternalHostApplication hostApplication)
    {
        this.hostApplication = hostApplication;
    }

    @Override
    public void issueSharedSecret(ApplicationLink applicationLink, String path) throws JwtRegistrationFailedException
    {
        // generate secure shared secret
        String sharedSecret = SecretGenerator.generateUrlSafeSharedSecret(SigningAlgorithm.HS256);

        // pass shared secret to peer
        try
        {
            applicationLink.createAuthenticatedRequestFactory(Anonymous.class)
                    .createRequest(Request.MethodType.POST, path)
                    .addRequestParameters(
                            "myId", hostApplication.getId().get(),
                            "yourId", applicationLink.getId().toString(),
                            "secret", sharedSecret)
                    .execute(new ResponseHandler<Response>()
                    {
                        @Override
                        public void handle(Response response) throws ResponseException
                        {
                            if (!response.isSuccessful())
                            {
                                throw new ResponseException("Registration failed, received " +
                                        response.getStatusCode() + " " + response.getStatusText() +
                                        " from peer.");
                            }
                        }
                    });
        }
        catch (ResponseException e)
        {
            throw new JwtRegistrationFailedException(e);
        }
        catch (CredentialsRequiredException e)
        {
            // will not happen with an Anonymous authentication provider
            throw new IllegalStateException(e);
        }

        // store the shared secret on the application link
        applicationLink.putProperty(ATLASSIAN_JWT_SHARED_SECRET, sharedSecret);
    }

    @Override
    public void revokeSharedSecret(ApplicationLink applicationLink)
    {
        applicationLink.removeProperty(ATLASSIAN_JWT_SHARED_SECRET);
    }

}
