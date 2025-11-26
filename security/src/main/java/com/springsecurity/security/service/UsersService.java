package com.springsecurity.security.service;

import com.springsecurity.security.entity.Users;
import com.springsecurity.security.repository.UsersRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UsersService {
    private final UsersRepository usersRepository;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(10);

    public UsersService(UsersRepository usersRepository, AuthenticationManager authenticationManager, JWTService jwtService) {
        this.usersRepository = usersRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public Users register(Users user){
        log.info("User Service: Request to register: {}", user);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return usersRepository.saveAndFlush(user);
    }

    public String login(Users user){
        log.info("User Service: Request to login: {}", user);
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if(authentication.isAuthenticated()){
            return jwtService.generateToken(user.getUsername());
        }
        return  "fail";
    }

    public String getCurrentSecret() {
        return jwtService.getSecretKey();
    }
}
