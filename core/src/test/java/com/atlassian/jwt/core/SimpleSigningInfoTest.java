package com.atlassian.jwt.core;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.SigningInfo;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.interfaces.RSAPrivateKey;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;


@RunWith(MockitoJUnitRunner.class)
public class SimpleSigningInfoTest
{
    @Mock
    RSAPrivateKey privateKey;

    @Test
    public void testCreationOfRs256SigningInfo()
    {
        SigningInfo signingInfo = new SimpleSigningInfo(SigningAlgorithm.RS256, privateKey);

        assertEquals(SigningAlgorithm.RS256, signingInfo.getSigningAlgorithm());
        assertEquals(privateKey, signingInfo.getPrivateKey().get());
        assertFalse(signingInfo.getSharedSecret().isPresent());
    }

    @Test
    public void testCreationOfHs256SigningInfo()
    {
        SigningInfo signingInfo = new SimpleSigningInfo(SigningAlgorithm.HS256, "my shared secret");

        assertEquals(SigningAlgorithm.HS256, signingInfo.getSigningAlgorithm());
        assertEquals("my shared secret", signingInfo.getSharedSecret().get());
        assertFalse(signingInfo.getPrivateKey().isPresent());
    }


    @Test(expected = IllegalArgumentException.class)
    public void creatingSigningInfoWithHs256AndPrivateKeyShouldFail()
    {
        new SimpleSigningInfo(SigningAlgorithm.HS256, privateKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void creatingSigningInfoWithRs256AndSharedShouldFail()
    {
        new SimpleSigningInfo(SigningAlgorithm.RS256, "share secret");
    }
}
