package com.atlassian.jwt.core;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class JwtUtilTest
{
    @Test
    public void percentEncodedStringsAreSortedByCodePoint() throws UnsupportedEncodingException
    {
        List<String> encodedStrings = Arrays.asList(JwtUtil.percentEncode("a"), JwtUtil.percentEncode("A"), JwtUtil.percentEncode("b"), JwtUtil.percentEncode("B"));
        Collections.sort(encodedStrings);
        assertThat(encodedStrings, is(Arrays.asList("A", "B", "a", "b")));
    }
}
