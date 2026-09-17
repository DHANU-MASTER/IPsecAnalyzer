package com.ipsec.security.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;

@Service
public class JwtTokenService {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenService.class);

    /** Known insecure development defaults; a warning is logged when one is in use. */
    private static final List<String> INSECURE_DEFAULTS = Arrays.asList(
        "your-super-secret-key-change-in-prod",
        "your-secret-key-change-in-prod",
        "change-me-to-a-random-64-char-secret-before-deploying-abcdef0123456789"
    );
    
    @Value("${security.jwt.secret:your-super-secret-key-minimum-32-chars-long-for-hs512}")
    private String secretKeyString;
    
    @Value("${security.jwt.expiration:3600000}")
    private long expirationMs;
    
    @PostConstruct
    void warnOnInsecureSecret() {
        if (INSECURE_DEFAULTS.contains(secretKeyString)) {
            logger.warn("JWT secret is still set to a default value. "
                + "Set the JWT_SECRET environment variable before deploying to production.");
        }
        if (secretKeyString != null && secretKeyString.getBytes(StandardCharsets.UTF_8).length < 32) {
            logger.warn("JWT secret is shorter than 32 bytes and will be padded; "
                + "use a longer random secret for production.");
        }
    }

    private Key getSigningKey() {
        byte[] keyBytes = secretKeyString.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, Math.min(keyBytes.length, 32));
            keyBytes = padded;
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    public String generateToken(Long userId, String username, String ipAddress) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("ipAddress", ipAddress);
        claims.put("issuedAt", System.currentTimeMillis());
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }
    
    public Claims validateToken(String token) throws JwtException {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
    
    public String getUsernameFromToken(String token) throws JwtException {
        Claims claims = validateToken(token);
        return claims.getSubject() != null ? claims.getSubject() : (String) claims.get("username");
    }
    
    public Long getUserIdFromToken(String token) throws JwtException {
        Claims claims = validateToken(token);
        Object idObj = claims.get("userId");
        if (idObj instanceof Number) {
            return ((Number) idObj).longValue();
        }
        return 1L;
    }
    
    public String getIpFromToken(String token) throws JwtException {
        Claims claims = validateToken(token);
        return (String) claims.get("ipAddress");
    }
}
