package com.springsecurity.security.config;

import com.springsecurity.security.service.JWTService;
import com.springsecurity.security.service.MyUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
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
                path.startsWith("/oauth2/") ||           // ✅ Add this
                path.startsWith("/login/oauth2/")) {     // ✅ Add this
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

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            UserDetails userDetails = myUserService.loadUserByUsername(username);
            if(jwtService.validateToken(authToken, userDetails)){
//                assert userDetails != null;
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(token);
            }
        }
        filterChain.doFilter(request, response);
    }

}
