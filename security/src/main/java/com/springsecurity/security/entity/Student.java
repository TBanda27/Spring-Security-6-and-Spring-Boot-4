package com.springsecurity.security.entity;

import lombok.Data;

@Data
public class Student {
    private Long id;
    private String firstName;
    private String lastName;

    public Student(Long id, String firstName, String lastName) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
    }
}
