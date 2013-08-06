package com.atlassian.auth.jwt.core;

import com.atlassian.auth.jwt.core.except.JwtSigningException;
import com.nimbusds.jose.*;

/**
 * Author: pbrownlow
 * Date: 30/07/13
 * Time: 5:16 PM
 */
public class NimbusJwtWriter implements JwtWriter
{
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private final static String JWT = "JWT";

    public NimbusJwtWriter(JWSAlgorithm algorithm, JWSSigner signer)
    {
        this.algorithm = algorithm;
        this.signer = signer;
    }

    @Override
    public String jsonToJwt(String json) throws JwtSigningException
    {
        // Create JWS header with HS256 algorithm
        JWSHeader header = new JWSHeader(algorithm);
        header.setType(new JOSEObjectType(JWT));

        // Create JWS object
        JWSObject jwsObject = new JWSObject(header, new Payload(json));

        try
        {
            jwsObject.sign(signer);
        }
        catch (JOSEException e)
        {
            throw new JwtSigningException(e);
        }

        // Serialise JWS object to compact format
        return jwsObject.serialize();
    }
}
