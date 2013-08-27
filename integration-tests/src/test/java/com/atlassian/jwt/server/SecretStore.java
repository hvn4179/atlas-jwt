package com.atlassian.jwt.server;

public class SecretStore
{
    /**
     * ID of the Jetty peer
     */
    private String clientId;
    /**
     * ID of the Atlassian app
     */
    private String serverId;
    /**
     * Shared secret for HMAC
     */
    private String secret;

    public SecretStore()
    {
    }

    public void update(String cliendId, String serverId, String secret)
    {
        this.clientId = cliendId;
        this.serverId = serverId;
        this.secret = secret;
    }

    public void clear()
    {
        update(null, null, null);
    }

    public String getClientId()
    {
        return clientId;
    }

    public String getServerId()
    {
        return serverId;
    }

    public String getSecret()
    {
        return secret;
    }
}
