package com.atlassian.jwt.internal;

import com.atlassian.jwt.JwtIssuer;
import com.atlassian.jwt.JwtIssuerRegistry;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PluginJwtRegistryTest
{
    private static final String ISSUER_NAME = "issuer-name";

    @Mock
    private BundleContext bundleContext;
    @Mock
    private JwtIssuerRegistry osgiRegistry;
    @Mock
    private JwtIssuer issuer;
    @Mock
    private ServiceReference serviceReference;
    private PluginJwtRegistry registry;

    @Before
    public void beforeEachTest() throws InvalidSyntaxException
    {
        when(bundleContext.getServiceReferences(eq(JwtIssuerRegistry.class.getName()), anyString()))
                .thenReturn(new ServiceReference[]{serviceReference});
        when(bundleContext.getService(serviceReference)).thenReturn(osgiRegistry);
        when(osgiRegistry.getIssuer(ISSUER_NAME)).thenReturn(issuer);

        registry = new PluginJwtRegistry(bundleContext);
    }

    @Test(expected = JwtUnknownIssuerException.class)
    public void gettingSharedSecretUsingApplinkIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        registry.getSharedSecret("no-such-issuer");
    }

    @Test(expected = NullPointerException.class)
    public void gettingSharedSecretUsingNullIssuerIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        registry.getSharedSecret(null);
    }

    @Test(expected = JwtIssuerLacksSharedSecretException.class)
    public void gettingSharedSecretUsingNoAuthAddOnIdResultsInException() throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException
    {
        registry.getSharedSecret(ISSUER_NAME);
    }

}