package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.NimbusUtil;
import com.atlassian.jwt.exception.JwtSigningException;
import com.atlassian.jwt.writer.JwtWriter;
import com.nimbusds.jose.*;

public class NimbusJwtWriter implements JwtWriter
{
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private final static String JWT = "JWT";

    public NimbusJwtWriter(SigningAlgorithm algorithm, JWSSigner signer)
    {
        this(NimbusUtil.asNimbusJWSAlgorithm(algorithm), signer);
    }

    protected NimbusJwtWriter(JWSAlgorithm algorithm, JWSSigner signer)
    {
        this.algorithm = algorithm;
        this.signer = signer;
    }

    @Override
    public String jsonToJwt(String json) throws JwtSigningException
    {
        // Serialise JWS object to compact format
        return generateJwsObject(json).serialize();
    }

    @Override
    public String sign(String signingInput)
    {
        try
        {
            return signer.sign(new JWSHeader(algorithm), signingInput.getBytes()).toString();
        }
        catch (JOSEException e)
        {
            throw new JwtSigningException(e);
        }
    }

    private JWSObject generateJwsObject(String payload)
    {
        JWSHeader header = new JWSHeader(algorithm);
        header.setType(new JOSEObjectType(JWT));

        // Create JWS object
        JWSObject jwsObject = new JWSObject(header, new Payload(payload));

        try
        {
            jwsObject.sign(signer);
        }
        catch (JOSEException e)
        {
            throw new JwtSigningException(e);
        }
        return jwsObject;
    }
}
