package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.HttpRequestCanonicalizer;
import com.atlassian.jwt.reader.JwtClaimVerifier;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

public class JwtClaimVerifiersBuilder
{
    /**
     * Tell {@link com.atlassian.jwt.reader.JwtReader}.read() that no custom claims are mandatory.
     */
    public static final Map<String, JwtClaimVerifier> NO_REQUIRED_CLAIMS = Collections.emptyMap();

    /**
     * Encapsulate the building of requirements that we place upon JWTs in incoming requests.
     * @param request Incoming request
     * @return {@link Map} of claim name to verifier for claims upon which we place requirements
     * @throws {@link IOException}, {@link NoSuchAlgorithmException}
     */
    public static Map<String, ? extends JwtClaimVerifier> build(CanonicalHttpRequest request) throws UnsupportedEncodingException, NoSuchAlgorithmException
    {
        return Collections.singletonMap(JwtConstants.Claims.QUERY_HASH, new JwtClaimEqualityVerifier(JwtConstants.Claims.QUERY_HASH, HttpRequestCanonicalizer.computeCanonicalRequestHash(request)));
    }
}
