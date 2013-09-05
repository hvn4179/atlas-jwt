package com.atlassian.jwt.core;

import com.atlassian.jwt.SigningAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JwtUtilTest
{
    private HttpServletRequest request;

    @Before
    public void beforeEachTest()
    {
        request = mock(HttpServletRequest.class);

        Map<String, String[]> queryParameters = new HashMap<String, String[]>();
        queryParameters.put("zee_last", new String[]{"param"});
        queryParameters.put("repeated", new String[]{"parameter 1","parameter 2"});
        queryParameters.put("first", new String[]{"param"});
        queryParameters.put(JwtUtil.JWT_PARAM_NAME, new String[]{"should.be.ignored"});
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/path/to/service/");
        when(request.getParameterMap()).thenReturn(queryParameters);
    }

    @Test
    public void computeCorrectQuerySignature() throws JOSEException, IOException
    {
        String sharedSecret = "shared secret";
        JWSSigner signer = new MACSigner(sharedSecret);
        String expected = new HmacJwtSigner(sharedSecret).signHmac256(JwtUtil.canonicalizeQuery(request));
        assertThat(JwtUtil.computeQuerySignature(SigningAlgorithm.HS256, signer, request), is(expected));
    }

    @Test
    public void computeCorrectCanonicalizedQuery() throws IOException
    {
        String expected = new StringBuilder()
                .append("GET").append('&')
                .append("/path/to/service").append('&')
                .append("first=param&repeated=parameter%201,parameter%202&zee_last=param").append('&')
                .toString();
        assertThat(JwtUtil.canonicalizeQuery(request), is(expected));
    }
}
