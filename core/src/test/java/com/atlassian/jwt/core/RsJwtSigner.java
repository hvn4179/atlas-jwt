package com.atlassian.jwt.core;

import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString;

public class RsJwtSigner
{
    private final String privateKeyFilename;

    public RsJwtSigner(String privateKeyFilename)
    {
        this.privateKeyFilename = privateKeyFilename;
    }

    public String jsonToRs256Jwt(Object... claims)
    {
        if (claims.length % 2 != 0)
        {
            throw new IllegalArgumentException("Must be an even number of arguments!");
        }

        JSONObject obj = new JSONObject();
        for (int i = 0; i < claims.length; i += 2)
        {
            if (!(claims[i] instanceof String))
            {
                throw new IllegalArgumentException("Expected object of type String at index " + i);
            }
            obj.put((String) claims[i], claims[i + 1]);
        }

        return jsonToRs256Jwt(obj.toJSONString());
    }

    public String jsonToRs256Jwt(String jsonPayload)
    {
        String jwtHeader = new JSONObject(ImmutableMap.of("alg", "RS256", "typ", "JWT")).toJSONString();
        String signingInput = encodeBase64URLSafeString(jwtHeader.getBytes()) + "." + encodeBase64URLSafeString(jsonPayload.getBytes());
        return signingInput + "." + signRs256(signingInput);
    }

    public String signRs256(String signingInput)
    {
//        try
//        {
//            InputStream in = this.getClass().getClassLoader()
//                    .getResourceAsStream(privateKeyFilename);
//
//            return encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()));
//        }
//        catch (NoSuchAlgorithmException e)
//        {
//            throw new IllegalStateException("Couldn't find SHA-256 digest!", e);
//        }
//        catch (InvalidKeyException e)
//        {
//            throw new IllegalStateException("Bad secret key '" + sharedSecret + "'!", e);
//        }
        return null;
    }
}
