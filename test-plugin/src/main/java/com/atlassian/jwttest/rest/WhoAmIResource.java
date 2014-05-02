package com.atlassian.jwttest.rest;

import com.atlassian.plugins.rest.common.security.AnonymousAllowed;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("whoami")
@AnonymousAllowed
public class WhoAmIResource
{
    @GET
    public Response whoAmI()
    {
        String username = RequestSubjectStore.getSubject();
        if (username == null)
        {
            username = "anonymous";
        }
        return Response.ok(username).build();
    }

}
