package com.atlassian.jwt.core;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import static junit.framework.Assert.assertEquals;

/**
 *
 */
public class JsonUtils
{
    public static void assertJsonContains(String payload, Object... claims) throws ParseException
    {
        assertJsonContains(payload, false, claims);
    }

    public static void assertJsonContainsOnly(String payload, Object... claims) throws ParseException
    {
        assertJsonContains(payload, true, claims);
    }

    public static void assertJsonContains(String payload, boolean onlyThese, Object... claims) throws ParseException
    {
        JSONObject obj = (JSONObject) new JSONParser(JSONParser.MODE_RFC4627).parse(payload);
        for (int i = 0; i < claims.length; i += 2)
        {
            String claim = (String) claims[i];
            Object expected = claims[i + 1];
            Object val = obj.get(claim);
            assertEquals("Unexpected value for claim '" + claim + "'", expected, val);
        }
        if (onlyThese)
        {
            assertEquals("Incorrect number of payload values", claims.length / 2, obj.keySet().size());
        }
    }
}
