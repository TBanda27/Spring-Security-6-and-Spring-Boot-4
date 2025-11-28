package com.springsecurity.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JWTService {
    // DON'T generate random keys
    @Value("${jwt.secret}")
    private String secretKey;

    public String generateToken(String username) {
        Map<String,Object> claims = new HashMap<>();
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiresAt = new Date(System.currentTimeMillis() + 60*1000); // 1 minute for testing

        log.info("Creating token for user: {} | Issued at: {} | Expires at: {}", username, issuedAt, expiresAt);

        return Jwts.builder()
                .header()
                .type("JWT")
                .and()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(issuedAt)
                .expiration(expiresAt)
                .and()
                .signWith(getKey())
                .compact();
    }

    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String extractUserName(String authToken) {
        return extractClaim(authToken, Claims::getSubject);
    }
    private <T> T extractClaim(String authToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(authToken);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String authToken) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(authToken)
                .getPayload();
    }

    public boolean validateToken(String authToken, UserDetails userDetails) {
        final String username = extractUserName(authToken);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(authToken));
    }

    public boolean isTokenExpired(String authToken) {
        Date expirationDate = extractExpiration(authToken);
        Date currentDate = new Date();
        boolean isExpired = expirationDate.before(currentDate);

        log.info("Token expiration check | Expires at: {} | Current time: {} | Is expired: {}",
                 expirationDate, currentDate, isExpired);

        return isExpired;
    }

    private Date extractExpiration(String authToken) {
        return extractClaim(authToken, Claims::getExpiration);
    }
}
