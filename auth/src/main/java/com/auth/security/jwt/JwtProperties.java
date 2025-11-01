package com.auth.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.jwt")
@ConfigurationPropertiesBinding
public class JwtProperties {
    private String secret;
    private int expiration;
    private int refreshExpiration = 604800000; // Default 7 days

    // Getters and setters
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
    
    public int getExpiration() { return expiration; }
    public void setExpiration(int expiration) { this.expiration = expiration; }
    
    public int getRefreshExpiration() { return refreshExpiration; }
    public void setRefreshExpiration(int refreshExpiration) { this.refreshExpiration = refreshExpiration; }
}