package com.atlassian.jwt.core.keys;

import com.atlassian.jwt.exception.JwtCannotRetrieveKeyException;
import org.junit.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyUtilsTest
{
    public static final String PRIVATE_KEY_PEM_FILE_NAME = "private.pem";
    public static final String PRIVATE_KEY_BOGUS_PEM_FILE_NAME = "private-bogus.pem";

    KeyUtils keyUtils = new KeyUtils();

    @Test
    public void testReadingPrivateKeyFromPemReader() throws Exception
    {
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(PRIVATE_KEY_PEM_FILE_NAME);
        RSAPrivateKey privateKey = keyUtils.readRsaPrivateKeyFromPem(new InputStreamReader(in));

        assertEquals("Key format does not match", "PKCS#8", privateKey.getFormat());
        assertEquals("Key algorithm does not match", "RSA", privateKey.getAlgorithm());

        // we got this expected hex string by running "openssl rsa -text -in <private-key-pem-file-name>", and formatting the 'private exponent' hex output by stripping out the ':' characters
        String expectedPrivateExponentHexString = "00925dc9f7900843e3b50cf3d1bf1669c5af0cec4bbeb16a69bce86031aae5f27e4d84987e0e78fd7046be2ada64aeab76fe77df900d132c1258c1bf25333521dec954323afcc75ba765b3bbcb2535c5d432a4bd8dbe9663f2a556b76a6518658a74e369c86736d2bd2b63b711d4b141bf5a2f01cd6e83a7bbba8fbec04ffa9df1";
        BigInteger expectedPrivateExponent = new BigInteger(expectedPrivateExponentHexString, 16);

        assertTrue("Key private exponent does not match", expectedPrivateExponent.compareTo(privateKey.getPrivateExponent()) == 0);
    }

    @Test(expected = JwtCannotRetrieveKeyException.class)
    public void testReadingBadPrivateKeyFromPemReaderFailsGracefully() throws Exception
    {
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(PRIVATE_KEY_BOGUS_PEM_FILE_NAME);
        keyUtils.readRsaPrivateKeyFromPem(new InputStreamReader(in));
    }
}
