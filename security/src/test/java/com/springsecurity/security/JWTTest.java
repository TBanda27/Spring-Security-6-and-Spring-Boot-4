package com.springsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTTest {

    private static final String SECRET_KEY = "eW91ci0yNTYtYml0LXNlY3JldC15b3VyLTI1Ni1iaXQtc2VjcmV0LXlvdXItMjU2LWJpdC1zZWNyZXQ=";

    public static void main(String[] args) {
        System.out.println("=== JWT Token Generation and Verification Test ===\n");

        // Generate token
        String token = generateToken("testuser");
        System.out.println("Generated Token:");
        System.out.println(token);
        System.out.println("\nToken Length: " + token.length());

        // Parse and display token parts
        String[] parts = token.split("\\.");
        System.out.println("\nToken Parts:");
        System.out.println("Header: " + parts[0]);
        System.out.println("Payload: " + parts[1]);
        System.out.println("Signature: " + parts[2] + " (length: " + parts[2].length() + ")");

        // Verify token
        System.out.println("\n=== Verification Test ===");
        boolean isValid = validateToken(token);
        System.out.println("Token Valid: " + isValid);

        if (isValid) {
            String username = extractUsername(token);
            System.out.println("Extracted Username: " + username);
        }

        // Test with the user's token
        System.out.println("\n=== Testing User's Token ===");
        String userToken = "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJ0YmFuZGEiLCJpYXQiOjE3NjQwMzE0MDksImV4cCI6MTc2NDAzMzIwOX0.XKxxiQFYMBQk13LBLnz6T1zc-MeZeWZMgllvJgRkfpLrUH40WRxFAWkvnXKYcQEK";
        boolean userTokenValid = validateToken(userToken);
        System.out.println("User's Token Valid: " + userTokenValid);

        if (userTokenValid) {
            String username = extractUsername(userToken);
            System.out.println("Extracted Username: " + username);
        } else {
            System.out.println("❌ VALIDATION FAILED - Token signature does not match!");
        }
    }

    private static String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .and()
                .signWith(getKey())
                .compact();
    }

    private static Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private static boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            System.out.println("Validation Error: " + e.getMessage());
            return false;
        }
    }

    private static String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    private static io.jsonwebtoken.Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
