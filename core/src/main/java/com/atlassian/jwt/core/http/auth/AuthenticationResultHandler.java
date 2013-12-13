package com.atlassian.jwt.core.http.auth;

import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

public interface AuthenticationResultHandler<R, S>
{
    S createAndSendInternalError(Exception e, R response, String externallyVisibleMessage);

    S createAndSendBadRequestError(Exception e, R response, String externallyVisibleMessage);

    S createAndSendUnauthorisedFailure(Exception e, R response, String externallyVisibleMessage);

    S createAndSendForbiddenError(Exception e, R response);

    S success(String message, Principal principal);
}
