package com.atlassian.jwt.internal.applinks;

import com.atlassian.applinks.api.ApplicationLink;
import com.atlassian.applinks.api.ApplicationLinkService;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.applinks.JwtApplinkFinderImpl;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.UUID;

import static com.atlassian.jwt.JwtConstants.AppLinks.SHARED_SECRET_PROPERTY_NAME;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApplinksJwtIssuerServiceTest
{
    private ApplinksJwtIssuerService applinksJwtIssuerService;
    @Mock private ApplicationLinkService applicationLinkService;
    @Mock private ApplicationLink applicationLink;
    @Mock private ApplicationLink unrelatedNoAuthApplicationLink;
    @Mock private ApplicationLink unrelatedOAuthApplicationLink;

    private static final String ADD_ON_KEY = "add-on key, uses JWT";
    private static final String NO_AUTH_ADD_ON_KEY = "no auth method on app link";
    private static final String OAUTH_ADD_ON_KEY = "app link says to use OAUTH1";
    private static final String APP_LINK_ID = UUID.randomUUID().toString();
    private static final String SHARED_SECRET = "shared secret";

    @Test
    public void validAddOnKeyIsValidIssuerId()
    {
        assertThat(applinksJwtIssuerService.isValid(ADD_ON_KEY), is(true));
    }

    @Test
    public void validApplinkIdIsInvalidIssuerId()
    {
        assertThat(applinksJwtIssuerService.isValid(APP_LINK_ID), is(false));
    }

    @Test
    public void nullIsInvalidIssuerId()
    {
        assertThat(applinksJwtIssuerService.isValid(null), is(false));
    }

    @Test
    public void addOnWithNonJwtAuthenticationIsInvalidIssuer()
    {
        assertThat(applinksJwtIssuerService.isValid(OAUTH_ADD_ON_KEY), is(false));
    }

    @Test
    public void addOnWithNullAuthenticationPropertyIsInvalidIssuer()
    {
        assertThat(applinksJwtIssuerService.isValid(NO_AUTH_ADD_ON_KEY), is(false));
    }

    @Test
    public void validAddOnKeyHasSharedSecret() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        assertThat(applinksJwtIssuerService.getSharedSecret(ADD_ON_KEY), is(SHARED_SECRET));
    }

    @Test(expected = JwtUnknownIssuerException.class)
    public void gettingSharedSecretUsingApplinkIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        applinksJwtIssuerService.getSharedSecret(APP_LINK_ID);
    }

    @Test(expected = JwtUnknownIssuerException.class)
    public void gettingSharedSecretUsingNullIssuerIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        applinksJwtIssuerService.getSharedSecret(null);
    }

    @Test(expected = JwtUnknownIssuerException.class)
    public void gettingSharedSecretUsingNoAuthAddOnIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        applinksJwtIssuerService.getSharedSecret(NO_AUTH_ADD_ON_KEY);
    }

    @Test(expected = JwtUnknownIssuerException.class)
    public void gettingSharedSecretUsingOAuthAddOnIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        applinksJwtIssuerService.getSharedSecret(OAUTH_ADD_ON_KEY);
    }

    @Before
    public void beforeEachTest()
    {
        when(unrelatedOAuthApplicationLink.getProperty(JwtConstants.AppLinks.ADD_ON_ID_PROPERTY_NAME)).thenReturn(OAUTH_ADD_ON_KEY);

        when(unrelatedNoAuthApplicationLink.getProperty(JwtConstants.AppLinks.ADD_ON_ID_PROPERTY_NAME)).thenReturn(NO_AUTH_ADD_ON_KEY);
        when(unrelatedNoAuthApplicationLink.getProperty(JwtConstants.AppLinks.AUTH_METHOD_PROPERTY_NAME)).thenReturn("OAUTH1");

        when(applicationLink.getProperty(JwtConstants.AppLinks.ADD_ON_ID_PROPERTY_NAME)).thenReturn(ADD_ON_KEY);
        when(applicationLink.getProperty(SHARED_SECRET_PROPERTY_NAME)).thenReturn(SHARED_SECRET);
        when(applicationLink.getProperty(JwtConstants.AppLinks.AUTH_METHOD_PROPERTY_NAME)).thenReturn(JwtConstants.AppLinks.JWT_AUTH_METHOD_NAME);

        when(applicationLinkService.getApplicationLinks()).thenReturn(asList(applicationLink, unrelatedNoAuthApplicationLink, unrelatedOAuthApplicationLink));

        applinksJwtIssuerService = new ApplinksJwtIssuerService(new JwtApplinkFinderImpl(applicationLinkService));
    }
}
