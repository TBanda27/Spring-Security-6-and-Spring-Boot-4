package com.springsecurity.security.controller;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping
    public String greet(HttpServletRequest request) {
        return "Hello: Welcome to Spring Security! "+request.getSession().getId();
    }
}
