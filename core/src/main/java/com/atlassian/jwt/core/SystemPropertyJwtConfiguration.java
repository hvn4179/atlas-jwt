package com.atlassian.jwt.core;

import com.atlassian.jwt.core.reader.NimbusJwtReaderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class SystemPropertyJwtConfiguration implements JwtConfiguration
{
    private static final Logger log = LoggerFactory.getLogger(NimbusJwtReaderFactory.class);

    private static final String JWT_MAX_LIFETIME_PROPERTY = "atlassian.jwt.token.lifetime.max";
    private static final int JWT_MAX_LIFETIME_DEFAULT = 60 * 60 * 1000; // one hour

    private final long maxJwtLifetime;

    public SystemPropertyJwtConfiguration()
    {
        maxJwtLifetime = parseLongSystemProperty(JWT_MAX_LIFETIME_PROPERTY, JWT_MAX_LIFETIME_DEFAULT);
    }

    private static long parseLongSystemProperty(String propertyName, long defaultValue)
    {
        long jwtMax;
        String maxJwtLifetimeProperty = System.getProperty(propertyName);
        if (maxJwtLifetimeProperty != null)
        {
            try
            {
                jwtMax = Long.valueOf(maxJwtLifetimeProperty);
            }
            catch (NumberFormatException e)
            {
                log.error("Failed to parse system property " + maxJwtLifetimeProperty + " value '" +
                        maxJwtLifetimeProperty + "'. Must be a number.", e);
                jwtMax = defaultValue;
            }
        }
        else
        {
            jwtMax = defaultValue;
        }
        return jwtMax;
    }

    public long getMaxJwtLifetime()
    {
        return maxJwtLifetime;
    }

}
