package com.atlassian.auth.jwt.core;

/**
 * Author: pbrownlow
 * Date: 6/08/13
 * Time: 10:21 AM
 */
public interface JwtIssuerToAccountNameMapper
{
    public String get(String issuer);
}
