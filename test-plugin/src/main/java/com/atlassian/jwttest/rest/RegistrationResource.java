package com.atlassian.jwttest.rest;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationType;
import com.atlassian.applinks.api.application.generic.GenericApplicationType;
import com.atlassian.applinks.spi.link.ApplicationLinkDetails;
import com.atlassian.applinks.spi.link.MutatingApplicationLinkService;
import com.atlassian.applinks.spi.util.TypeAccessor;
import com.atlassian.jwt.applinks.JwtApplinkConstants;
import com.atlassian.jwt.applinks.JwtApplinkFinder;
import com.atlassian.jwt.applinks.JwtPeerService;
import com.atlassian.plugins.rest.common.security.AnonymousAllowed;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.UUID;

/**
 *
 */
@Path("register")
@AnonymousAllowed
public class RegistrationResource
{
    private final MutatingApplicationLinkService applicationLinkService;
    private final TypeAccessor typeAccessor;
    private final JwtPeerService peerService;
    private final JwtApplinkFinder jwtApplinkFinder;

    public RegistrationResource(MutatingApplicationLinkService applicationLinkService, TypeAccessor typeAccessor, JwtPeerService peerService, JwtApplinkFinder jwtApplinkFinder)
    {
        this.applicationLinkService = applicationLinkService;
        this.typeAccessor = typeAccessor;
        this.peerService = peerService;
        this.jwtApplinkFinder = jwtApplinkFinder;
    }

    @POST
    public Response register(@FormParam("baseUrl") String baseUrl, @FormParam("path") String path) throws Exception
    {
        URI uri = URI.create(baseUrl);

        ApplicationLinkDetails applinkDetails = ApplicationLinkDetails.builder().rpcUrl(uri).name("Test JWT Peer").build();
        // TODO GenericApplicationTypeImpl should implement GenericApplicationType!
        ApplicationType applicationType = typeAccessor.getApplicationType(GenericApplicationType.class);
        ApplicationLink applink = applicationLinkService.createApplicationLink(applicationType, applinkDetails);
        applink.putProperty(JwtApplinkConstants.PLUGIN_KEY_PROPERTY, UUID.randomUUID().toString());
        applink.putProperty(JwtApplinkConstants.AUTH_METHOD_PROPERTY, JwtApplinkConstants.JWT_AUTH_METHOD);
        peerService.issueSharedSecret(applink, path);

        return Response.ok().build();
    }

    @DELETE
    @Path("{id}")
    public Response delete(@PathParam("id") String id) throws Exception
    {
        ApplicationLink applink = jwtApplinkFinder.find(id);
        if (applink == null)
        {
            return Response.status(Response.Status.NOT_FOUND).entity("No applink with id " + id).build();
        }
        applicationLinkService.deleteApplicationLink(applink);
        return Response.noContent().build();
    }

}
