package com.atlassian.jwt.core;

import com.atlassian.jwt.JwtWriter;
import com.atlassian.jwt.exception.JwtSigningException;
import com.nimbusds.jose.*;

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
