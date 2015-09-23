package com.atlassian.jwt.internal.writer;

import com.atlassian.jwt.writer.JwtClaimWriter;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import com.atlassian.jwt.writer.JwtJsonBuilderFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PluggableJwtJsonBuilderFactoryTest
{
    @Mock
    private BundleContext bundleContext;
    @Mock
    private JwtJsonBuilder delegateBuilder;
    @Mock
    private JwtJsonBuilderFactory delegateFactory;
    @Mock
    private JwtClaimWriter writer1;
    @Mock
    private JwtClaimWriter writer2;
    private PluggableJwtJsonBuilderFactory factory;

    @Before
    public void setUp() throws InvalidSyntaxException
    {
        when(delegateFactory.jsonBuilder()).thenReturn(delegateBuilder);

        // mock an OSGI context with two registered writers
        ServiceReference serviceReference1 = mock(ServiceReference.class);
        ServiceReference serviceReference2 = mock(ServiceReference.class);
        when(bundleContext.getService(serviceReference1)).thenReturn(writer1);
        when(bundleContext.getService(serviceReference2)).thenReturn(writer2);
        when(bundleContext.getServiceReferences(eq(JwtClaimWriter.class.getName()), anyString()))
                .thenReturn(new ServiceReference[]{serviceReference1, serviceReference2});

        factory = new PluggableJwtJsonBuilderFactory(bundleContext);
        factory.setDelegate(delegateFactory);
        factory.onStart();

    }

    @Test
    public void testClaimWritersInvokedJustBeforeBuild()
    {
        JwtJsonBuilder builder = factory.jsonBuilder();

        assertNotNull(builder);
        verifyZeroInteractions(writer1, writer2);

        builder.issuer("issuer");
        verify(delegateBuilder).issuer("issuer");

        verifyZeroInteractions(writer1, writer2);

        // verify that the claim writers are invoked just before build
        builder.build();
        // the order of writers is not defined. We'll assume that if one writer gets called before delegate.build(),
        // all of them are
        InOrder inOrder = inOrder(delegateBuilder, writer1);
        inOrder.verify(writer1).write(delegateBuilder);
        verify(writer2).write(delegateBuilder);
        inOrder.verify(delegateBuilder).build();
    }

    @Test
    public void testDestroyClosesTracker()
    {
        factory.destroy();

        verify(bundleContext, times(2)).ungetService(any(ServiceReference.class));
    }
}