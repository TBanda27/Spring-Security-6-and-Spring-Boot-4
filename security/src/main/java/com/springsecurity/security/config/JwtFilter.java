package com.springsecurity.security.config;

import com.springsecurity.security.service.JWTService;
import com.springsecurity.security.service.MyUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final MyUserService myUserService;

    private final JWTService jwtService;

    public JwtFilter( MyUserService myUserService, JWTService jwtService) {
        this.myUserService = myUserService;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        // Skip JWT filter for these paths
        if (path.equals("/register") ||
                path.equals("/login") ||
                path.startsWith("/oauth2/") ||
                path.startsWith("/login/oauth2/")) {
            filterChain.doFilter(request, response);
            return;
        }
        String authHeader = request.getHeader("Authorization");
        String authToken = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            authToken = authHeader.substring(7);
            username = jwtService.extractUserName(authToken);
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = myUserService.loadUserByUsername(username);

            log.info("Validating JWT for user: {}", username);
            boolean isValid = jwtService.validateToken(authToken, userDetails);
            boolean isExpired = jwtService.isTokenExpired(authToken);
            log.info("Token valid: {}, Token expired: {}", isValid, isExpired);

            if (isValid) {
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(token);
                log.info("Authentication successful for user: {}", username);
            } else {
                log.warn("Token validation failed for user: {}", username);
            }
            filterChain.doFilter(request, response);
        }
    }
}
