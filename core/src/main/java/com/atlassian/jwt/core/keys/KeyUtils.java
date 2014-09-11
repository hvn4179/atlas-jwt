package com.atlassian.jwt.core.keys;

import com.atlassian.fugue.Either;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.File;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Useful utility functions for working with keys
 */
public class KeyUtils
{
    public static Either<Exception, RSAPrivateKey> readRsaKeyFromPem(Reader reader) throws Exception {
        PEMParser pemParser = new PEMParser(reader);
        try
        {
            Object object = pemParser.readObject();
            PEMKeyPair pemKeyPair = (PEMKeyPair) object;

            byte[] encodedPrivateKey = pemKeyPair.getPrivateKeyInfo().getEncoded();

            // Now convert to Java objects
            KeyFactory keyFactory = KeyFactory.getInstance( "RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            return Either.right(privateKey);
        } catch (Exception e)
        {
            return Either.left(e);
        }
    }

    public static RSAPrivateKey readRsaKeyFromPem(File file) {
        return null;
    }

    public static RSAPrivateKey readRsaKeyFromString(String string) {
        return null;
    }
}
