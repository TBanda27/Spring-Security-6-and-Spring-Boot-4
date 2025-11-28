package com.springsecurity.security.config;

import com.springsecurity.security.entity.Users;
import com.springsecurity.security.repository.UsersRepository;
import com.springsecurity.security.service.JWTService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTService jwtService;
    private final UsersRepository usersRepository;

    public OAuth2LoginSuccessHandler(JWTService jwtService, UsersRepository usersRepository) {
        this.jwtService = jwtService;
        this.usersRepository = usersRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // Extract user information from Google OAuth2
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        log.info("OAuth2 login success for user: {} ({})", name, email);

        Users user = usersRepository.findByUsername(email);
        if (user == null) {
            user = new Users();
            user.setUsername(email);
            user.setPassword("");
            user.setId(Math.abs((long) email.hashCode()));
            usersRepository.saveAndFlush(user);
            log.info("Created new OAuth2 user: {}", email);
        }

        String jwtToken = jwtService.generateToken(email);
        log.info("Generated JWT token for OAuth2 user: {}", email);

        Cookie jwtCookie = new Cookie("jwt", jwtToken);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(60);
        response.addCookie(jwtCookie);
        log.info("JWT token stored in cookie for user: {}", email);

        // Redirect to students page
        getRedirectStrategy().sendRedirect(request, response, "/students");
    }
}
