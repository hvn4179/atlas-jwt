package com.atlassian.jwt;

import com.atlassian.jwt.exception.JwsUnsupportedAlgorithmException;
import org.apache.commons.lang.StringUtils;

import java.util.Arrays;

/**
 * An enumeration of supported JWS algorithms. Values must match the names used in the JWT 'alg' claim. Valid values
 * are specified by <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14">JSON Web Algorithms</a>.
 */
public enum SigningAlgorithm
{
    HS256; // HMAC SHA-256

    public static SigningAlgorithm forName(String alg) throws JwsUnsupportedAlgorithmException
    {
        try
        {
            return SigningAlgorithm.valueOf(alg.toUpperCase());
        }
        catch (IllegalArgumentException e)
        {
            throw new JwsUnsupportedAlgorithmException(alg + " is not a supported JWS algorithm. Please try one of: [" +
                    StringUtils.join(Arrays.asList(SigningAlgorithm.values()), ",") + "]");
        }
    }

}
