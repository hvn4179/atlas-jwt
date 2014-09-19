package com.atlassian.jwt.core.writer;


import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.SigningInfo;
import com.google.common.base.Optional;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.interfaces.RSAPrivateKey;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class NimbusJwtWriterFactoryTest
{
    @Mock
    NimbusJwtWriterFactory.NimbusJwtWriterFactoryHelper mockFactoryHelper;

    @Mock
    RSAPrivateKey privateKey;

    @Mock
    SigningInfo signingInfo;

    @Test
    public void verifyCorrectCreationOfRsJwtWriter()
    {
        when(signingInfo.getSigningAlgorithm()).thenReturn(SigningAlgorithm.RS256);
        when(signingInfo.getPrivateKey()).thenReturn(Optional.of(privateKey));
        when(signingInfo.getSharedSecret()).thenReturn(Optional.<String>absent());

        NimbusJwtWriterFactory factory = new NimbusJwtWriterFactory(mockFactoryHelper);

        factory.signingWriter(signingInfo);

        verify(mockFactoryHelper).makeRsJwtWriter(eq(SigningAlgorithm.RS256), any(RSASSASigner.class));
        verify(mockFactoryHelper, never()).makeMacJwtWriter(any(SigningAlgorithm.class), any(MACSigner.class));
    }

    @Test
    public void verifyCorrectCreationOfMacJwtWriter()
    {
        when(signingInfo.getSigningAlgorithm()).thenReturn(SigningAlgorithm.HS256);
        when(signingInfo.getSharedSecret()).thenReturn(Optional.of("shared secret"));
        when(signingInfo.getPrivateKey()).thenReturn(Optional.<RSAPrivateKey>absent());

        NimbusJwtWriterFactory factory = new NimbusJwtWriterFactory(mockFactoryHelper);

        factory.signingWriter(signingInfo);

        verify(mockFactoryHelper).makeMacJwtWriter(eq(SigningAlgorithm.HS256), any(MACSigner.class));
        verify(mockFactoryHelper, never()).makeRsJwtWriter(any(SigningAlgorithm.class), any(RSASSASigner.class));
    }
}
