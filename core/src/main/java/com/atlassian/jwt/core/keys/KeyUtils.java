package com.atlassian.jwt.core.keys;

import com.atlassian.jwt.exception.JwtCannotRetrieveKeyException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.Reader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Useful utility functions for working with keys
 */
public class KeyUtils
{
    public RSAPrivateKey readRsaPrivateKeyFromPem(Reader reader) throws JwtCannotRetrieveKeyException
    {
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

            return privateKey;
        } catch (Exception e)
        {
            throw new JwtCannotRetrieveKeyException("Error reading private key",  e);
        }
        finally
        {
            IOUtils.closeQuietly(reader);
        }
    }

    public RSAPublicKey readRsaPublicKeyFromPem(Reader reader) throws JwtCannotRetrieveKeyException
    {
        PEMParser pemParser = new PEMParser(reader);
        try
        {
            Object object = pemParser.readObject();
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            SubjectPublicKeyInfo pub = SubjectPublicKeyInfo.getInstance(object);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            RSAPublicKey publicKey = (RSAPublicKey) converter.getPublicKey(pub);
            return publicKey;
        } catch (Exception e)
        {
            throw new JwtCannotRetrieveKeyException("Error reading public key",  e);
        }
        finally
        {
            IOUtils.closeQuietly(reader);
        }
    }
}
