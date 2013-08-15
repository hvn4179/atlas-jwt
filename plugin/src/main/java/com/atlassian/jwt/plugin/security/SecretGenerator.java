package com.atlassian.jwt.plugin.security;

import com.atlassian.jwt.JwsAlgorithm;
import com.atlassian.security.random.DefaultSecureRandomService;

public class SecretGenerator
{

    public static String generateSharedSecret(JwsAlgorithm alg) {
        // key length must equal length of HMAC output (http://tools.ietf.org/html/rfc4868#section-2.1.1)
        int length;
        switch (alg) {
            case HS256:
                length = 32;
                break;
            default:
                throw new IllegalArgumentException("Unrecognised " + JwsAlgorithm.class.getSimpleName() + ": " + alg);
        }

        byte[] bytes = new byte[length];
        DefaultSecureRandomService.getInstance().nextBytes(bytes);
        return new String(bytes);
    }

}
