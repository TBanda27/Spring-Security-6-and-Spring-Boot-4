package com.springsecurity.security.service;

import com.springsecurity.security.entity.Users;
import com.springsecurity.security.repository.UsersRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UsersService {
    private final UsersRepository usersRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(10);

    public UsersService(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    public Users register(Users user){
        log.info("User Controller: register: {}", user);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return usersRepository.saveAndFlush(user);
    }
}
