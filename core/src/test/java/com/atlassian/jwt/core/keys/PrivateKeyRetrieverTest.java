package com.atlassian.jwt.core.keys;

import com.atlassian.fugue.Either;
import com.atlassian.jwt.exception.JwtCannotRetrieveKeyException;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.InputStreamReader;
import java.security.interfaces.RSAPrivateKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PrivateKeyRetrieverTest
{
    @Mock
    private KeyUtils keyUtils;
    @Mock
    private RSAPrivateKey privateKey;
    @Mock
    Either<JwtCannotRetrieveKeyException, RSAPrivateKey> either;

    @Test
    public void shouldBeAbleToReadKeyFromClasspathResource()
    {
        PrivateKeyRetriever keyRetriever = new PrivateKeyRetrieverImpl(PrivateKeyRetriever.keyLocationType.CLASSPATH_RESOURCE,
                "private.pem", keyUtils);
        when(keyUtils.readRsaPrivateKeyFromPem(any(InputStreamReader.class))).thenReturn(Either.<JwtCannotRetrieveKeyException, RSAPrivateKey>right(privateKey));

        Either<JwtCannotRetrieveKeyException, RSAPrivateKey> result = keyRetriever.getPrivateKey();

        assertTrue(result.isRight());
        assertTrue(result.right().get() == privateKey);
    }

    @Test
    public void shouldGetErrorWhenKeyReadingFromClasspathResourceFails()
    {
        PrivateKeyRetriever keyRetriever = new PrivateKeyRetrieverImpl(PrivateKeyRetriever.keyLocationType.CLASSPATH_RESOURCE,
                "private.pem", keyUtils);

        when(keyUtils.readRsaPrivateKeyFromPem(any(InputStreamReader.class))).thenReturn(
                Either.<JwtCannotRetrieveKeyException, RSAPrivateKey>left(new JwtCannotRetrieveKeyException("Random error")));
        Either<JwtCannotRetrieveKeyException, RSAPrivateKey> result = keyRetriever.getPrivateKey();
        assertTrue(result.isLeft());
        assertEquals("Random error", result.left().get().getMessage());
    }

    @Test
    public void shouldGetErrorWhenClasspathResourceDoesNotExist()
    {
        PrivateKeyRetriever keyRetriever = new PrivateKeyRetrieverImpl(PrivateKeyRetriever.keyLocationType.CLASSPATH_RESOURCE,
                "non-existent-private.pem", keyUtils);

        Either<JwtCannotRetrieveKeyException, RSAPrivateKey> result = keyRetriever.getPrivateKey();
        assertTrue(result.isLeft());
        assertEquals("Could not load classpath resource non-existent-private.pem", result.left().get().getMessage());

    }

    @Test
    public void shouldBeAbleToReadKeyFromFile()
    {
        PrivateKeyRetriever keyRetriever = new PrivateKeyRetrieverImpl(PrivateKeyRetriever.keyLocationType.FILE,
                "target/test-classes/private.pem", keyUtils);

        when(keyUtils.readRsaPrivateKeyFromPem(any(InputStreamReader.class))).thenReturn(Either.<JwtCannotRetrieveKeyException, RSAPrivateKey>right(privateKey));

        Either<JwtCannotRetrieveKeyException, RSAPrivateKey> result = keyRetriever.getPrivateKey();

        assertTrue(result.isRight());
        assertTrue(result.right().get() == privateKey);

    }

    @Test
    public void shouldGetErrorWhenReadingKeyFromNonExistentFile()
    {
        PrivateKeyRetriever keyRetriever = new PrivateKeyRetrieverImpl(PrivateKeyRetriever.keyLocationType.FILE,
                "non-existent-file", keyUtils);


        Either<JwtCannotRetrieveKeyException, RSAPrivateKey> result = keyRetriever.getPrivateKey();

        assertTrue(result.isLeft());
        assertEquals("Private key file not found: non-existent-file", result.left().get().getMessage());

    }

}
