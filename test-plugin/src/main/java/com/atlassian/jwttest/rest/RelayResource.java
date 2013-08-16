package com.atlassian.jwttest.rest;

import com.atlassian.applinks.api.*;
import com.atlassian.applinks.api.auth.Anonymous;
import com.atlassian.jwt.applinks.JwtService;
import com.atlassian.plugins.rest.common.security.AnonymousAllowed;
import com.atlassian.sal.api.net.Request;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;

/**
 * Resource for relaying JWT authenticated requests to a {@link ApplicationLink linked application}.
 */
@Path("relay")
@AnonymousAllowed
public class RelayResource
{
    private final ApplicationLinkService applicationLinkService;
    private final JwtService jwtService;

    public RelayResource(ApplicationLinkService applicationLinkService, JwtService jwtService)
    {
        this.applicationLinkService = applicationLinkService;
        this.jwtService = jwtService;
    }

    @POST
    @Path("{id}")
    public Response relay(@PathParam("id") String id,
                          @FormParam("path") String path,
                          @FormParam("method") String method,
                          @FormParam("payload") String payload) throws Exception {
        ApplicationLink applink = applicationLinkService.getApplicationLink(new ApplicationId(id));
        if (applink == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("No applink with id " + id).build();
        }
        String jwt = jwtService.issueJwt(payload, applink);

        Request.MethodType methodType = Request.MethodType.valueOf(method.toUpperCase());
        ApplicationLinkRequest request = applink.createAuthenticatedRequestFactory(Anonymous.class)
                                                .createRequest(methodType, path);

        request.addHeader("Authorization", "JWT " + jwt);

        return Response.noContent().build();
    }

}
