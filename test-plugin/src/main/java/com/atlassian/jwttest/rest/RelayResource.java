package com.atlassian.jwttest.rest;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkRequest;
import com.atlassian.applinks.api.auth.Anonymous;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.plugins.rest.common.security.AnonymousAllowed;
import com.atlassian.sal.api.net.Request;
import com.atlassian.sal.api.net.ResponseException;
import com.atlassian.sal.api.net.ResponseHandler;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import java.util.concurrent.atomic.AtomicBoolean;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

/**
 * Resource for relaying JWT authenticated requests to a {@link ApplicationLink linked application}.
 */
@Path("relay")
@AnonymousAllowed
public class RelayResource
{
    public static final String MODE_HEADER = "header";
    public static final String MODE_QUERY = "query";

    private final JwtService jwtService;
    private final JwtApplinkFinder jwtApplinkFinder;

    public RelayResource(JwtService jwtService, JwtApplinkFinder jwtApplinkFinder)
    {
        this.jwtService = jwtService;
        this.jwtApplinkFinder = jwtApplinkFinder;
    }

    @POST
    @Path("{id}")
    public Response relay(@PathParam("id") String id,
                          @QueryParam("mode") @DefaultValue(MODE_HEADER) String mode,
                          @FormParam("path") String path,
                          @FormParam("method") String method,
                          @FormParam("payload") String payload) throws Exception
    {
        boolean jwtAsQueryParam = false;
        boolean jwtAsAuthzHeader = false;

        if (MODE_HEADER.equalsIgnoreCase(mode))
        {
            jwtAsAuthzHeader = true;
        }
        else if (MODE_QUERY.equals(mode))
        {
            jwtAsQueryParam = true;
        }
        else
        {
            return Response.status(BAD_REQUEST)
                    .entity("The 'mode' parameter must be set to 'header' or 'query'.")
                    .build();
        }

        ApplicationLink applink = jwtApplinkFinder.find(id);
        if (applink == null)
        {
            return Response.status(Response.Status.NOT_FOUND).entity("No applink with id " + id).build();
        }
        String jwt = jwtService.issueJwt(payload, (String)applink.getProperty(JwtConstants.AppLinks.SHARED_SECRET_PROPERTY_NAME));
        if (jwtAsQueryParam)
        {
            path += (path.contains("?") ? "&" : "?") + "jwt=" + jwt;
        }

        Request.MethodType methodType = Request.MethodType.valueOf(method.toUpperCase());
        ApplicationLinkRequest request = applink.createAuthenticatedRequestFactory(Anonymous.class)
                .createRequest(methodType, path);

        if (jwtAsAuthzHeader)
        {
            request.addHeader("Authorization", "JWT " + jwt);
        }

        final AtomicBoolean failed = new AtomicBoolean(false);
        final StringBuilder error = new StringBuilder();

        request.execute(new ResponseHandler<com.atlassian.sal.api.net.Response>()
        {
            @Override
            public void handle(com.atlassian.sal.api.net.Response response) throws ResponseException
            {
                if (!response.isSuccessful())
                {
                    failed.set(true);
                    error.append(response.getStatusCode()).append(" ").append(response.getResponseBodyAsString());
                }
            }
        });

        if (failed.get())
        {
            return Response.serverError().entity(error.toString()).build();
        }
        else
        {
            return Response.ok("OK").build();
        }
    }

}
