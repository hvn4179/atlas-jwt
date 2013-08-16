package com.atlassian.jwttest.rest;

import com.atlassian.plugins.rest.common.security.AnonymousAllowed;
import com.atlassian.sal.api.user.UserManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("whoami")
@AnonymousAllowed
public class WhoAmIResource
{
    private final UserManager userManager;

    public WhoAmIResource(UserManager userManager)
    {
        this.userManager = userManager;
    }

    @GET
    public Response whoAmI() {
        String username = userManager.getRemoteUsername();
        if (username == null)
        {
            username = "anonymous";
        }
        return Response.ok(username).build();
    }

}
