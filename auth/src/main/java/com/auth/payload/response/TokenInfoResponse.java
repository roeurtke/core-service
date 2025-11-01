package com.auth.payload.response;

import java.util.Map;

public class TokenInfoResponse {
    private String subject;
    private Long issuedAt;
    private Long expiresAt;
    private Map<String, Object> claims;

    public TokenInfoResponse(String subject, Long issuedAt, Long expiresAt, Map<String, Object> claims) {
        this.subject = subject;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.claims = claims;
    }

    public String getSubject() { return subject; }
    public Long getIssuedAt() { return issuedAt; }
    public Long getExpiresAt() { return expiresAt; }
    public Map<String, Object> getClaims() { return claims; }
}


