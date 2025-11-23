package com.springsecurity.security.controller;

import com.springsecurity.security.entity.Users;
import com.springsecurity.security.service.UsersService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class UsersController {
    private final UsersService usersService;

    public UsersController(UsersService usersService) {
        this.usersService = usersService;
    }

    @PostMapping("/register")
    public Users saveUser(@RequestBody Users user) {
        log.info("User Controller: saveUser: {}", user);
        return usersService.register(user);
    }

}
