package com.atlassian.jwt.util;

/**
 *
 */
public interface Consumer<T>
{
    void consume(T t);
}
