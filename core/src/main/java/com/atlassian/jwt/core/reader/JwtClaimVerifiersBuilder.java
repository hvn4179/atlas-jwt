package com.atlassian.jwt.core.reader;

import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.JwtConstants;
import com.atlassian.jwt.core.HttpRequestCanonicalizer;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReader;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
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
     * @param reader Reader that will parse and verify the incoming request, in part by using the returned {@link JwtClaimVerifier}s
     * @return {@link Map} of claim name to verifier for claims upon which we place requirements
     * @throws IOException
     */
    public static Map<String, JwtClaimVerifier> build(CanonicalHttpRequest request, JwtReader reader) throws IOException
    {
        Map<String, String> signedClaimSigningInputs = Collections.singletonMap(JwtConstants.Claims.QUERY_SIGNATURE, HttpRequestCanonicalizer.canonicalize(request));
        return buildNameToVerifierMap(signedClaimSigningInputs, reader);
    }

    /**
     * @param signedClaimSigningInputs {@link java.util.Map} of claim name to corresponding input to signing algorithm
     * @param reader {@link com.atlassian.jwt.reader.JwtReader} that will read the JWT message
     * @return {@link java.util.Map} of claim name to {@link com.atlassian.jwt.reader.JwtClaimVerifier} capable of verifying every specified claim
     */
    public static Map<String, JwtClaimVerifier> buildNameToVerifierMap(Map<String, String> signedClaimSigningInputs, JwtReader reader)
    {
        Map<String, JwtClaimVerifier> claimVerifiers = new HashMap<String, JwtClaimVerifier>(signedClaimSigningInputs.size());

        for (Map.Entry<String, String> claimAndSigningInput : signedClaimSigningInputs.entrySet())
        {
            String claimName = claimAndSigningInput.getKey();
            claimVerifiers.put(claimName, reader.createSignedClaimVerifier(claimAndSigningInput.getValue(), claimName));
        }

        return claimVerifiers;
    }
}
