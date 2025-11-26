package com.springsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTValidationTest {

    // This is the secret key from application.yaml
    private static final String SECRET_KEY = "eW91ci0yNTYtYml0LXNlY3JldC15b3VyLTI1Ni1iaXQtc2VjcmV0LXlvdXItMjU2LWJpdC1zZWNyZXQ=";

    public static void main(String[] args) {
        System.out.println("=== JWT Token Generation and Validation Test ===\n");
        System.out.println("Using Fixed Secret Key from application.yaml");
        System.out.println("Secret: " + SECRET_KEY + "\n");

        // Test 1: Generate a new token
        System.out.println("--- Test 1: Generate New Token ---");
        String token1 = generateToken("testuser");
        System.out.println("Generated Token:");
        System.out.println(token1);
        System.out.println("\nValidating token1: " + validateToken(token1));
        if (validateToken(token1)) {
            System.out.println("✅ Username extracted: " + extractUsername(token1));
        }

        // Test 2: Generate another token with same secret (simulating app restart)
        System.out.println("\n--- Test 2: Generate Second Token (Simulating App Restart) ---");
        String token2 = generateToken("anotheruser");
        System.out.println("Generated Token:");
        System.out.println(token2);
        System.out.println("\nValidating token2: " + validateToken(token2));
        if (validateToken(token2)) {
            System.out.println("✅ Username extracted: " + extractUsername(token2));
        }

        // Test 3: Validate token1 again (proving it still works after "restart")
        System.out.println("\n--- Test 3: Re-validate First Token (After Simulated Restart) ---");
        System.out.println("Validating token1 again: " + validateToken(token1));
        if (validateToken(token1)) {
            System.out.println("✅ Token1 still valid! Username: " + extractUsername(token1));
        }

        // Test 4: Test the user's existing token from screenshot
        System.out.println("\n--- Test 4: Validate Existing Token ---");
        String existingToken = "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJ0YmFuZGEiLCJpYXQiOjE3NjQwMzE0MDksImV4cCI6MTc2NDAzMzIwOX0.XKxxiQFYMBQk13LBLnz6T1zc-MeZeWZMgllvJgRkfpLrUH40WRxFAWkvnXKYcQEK";
        boolean existingValid = validateToken(existingToken);
        System.out.println("Existing token valid: " + existingValid);
        if (!existingValid) {
            System.out.println("❌ This token was signed with a DIFFERENT secret key (before the fix)");
        } else {
            System.out.println("✅ Username: " + extractUsername(existingToken));
        }

        System.out.println("\n=== Instructions for jwt.io ===");
        System.out.println("1. Go to https://jwt.io");
        System.out.println("2. Paste one of the tokens above in the 'Encoded' section");
        System.out.println("3. In the 'Verify Signature' section, paste this secret:");
        System.out.println("   " + SECRET_KEY);
        System.out.println("4. You should see 'Signature Verified' in blue");
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

    private static SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private static boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            System.out.println("   Validation Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        }
    }

    private static String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    private static Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
