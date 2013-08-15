package com.atlassian.jwt;

import com.atlassian.jwt.exception.JwsUnsupportedAlgorithmException;
import com.sun.deploy.util.StringUtils;

import java.util.Arrays;

/**
 * An enumeration of supported JWS algorithms. Values must match the names used in the JWT 'alg' claim. Valid values
 * are specified by <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14">JSON Web Algorithms</a>.
 */
public enum JwsAlgorithm
{
    HS256; // HMAC SHA-256

    public JwsAlgorithm forName(String alg) throws JwsUnsupportedAlgorithmException
    {
        try
        {
            return JwsAlgorithm.valueOf(alg.toUpperCase());
        }
        catch (IllegalArgumentException e)
        {
            throw new JwsUnsupportedAlgorithmException(alg + " is not a supported JWS algorithm. Please try one of: [" +
                    StringUtils.join(Arrays.asList(JwsAlgorithm.values()), ",") + "]");
        }
    }

}
