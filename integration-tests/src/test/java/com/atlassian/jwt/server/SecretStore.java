package com.atlassian.jwt.server;

public class SecretStore
{
    private String id;
    private String secret;

    public void update(String id, String secret) {
        this.id = id;
        this.secret = secret;
    }

    public void clear() {
        update(null, null);
    }

    public String getId() {
        return id;
    }

    public String getSecret() {
        return secret;
    }
}
