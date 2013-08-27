package com.atlassian.jwt.core.writer;

import com.atlassian.jwt.writer.JwtJsonBuilder;
import com.atlassian.jwt.writer.JwtJsonBuilderFactory;

/**
 *
 */
public class JsonSmartJwtJsonBuilderFactory implements JwtJsonBuilderFactory
{
    @Override
    public JwtJsonBuilder jsonBuilder()
    {
        return new JsonSmartJwtJsonBuilder();
    }
}
