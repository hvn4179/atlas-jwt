package com.atlassian.jwt.writer;

/**
 * Factory for {@link JwtJsonBuilder}.
 *
 * @since 1.0
 */
public interface JwtJsonBuilderFactory
{
    /**
     * @return a {@link JwtJsonBuilder}.
     */
    JwtJsonBuilder jsonBuilder();
}
