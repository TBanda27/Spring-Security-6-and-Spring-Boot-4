package com.springsecurity.security.controller;

import com.springsecurity.security.entity.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class StudentController {

    List<Student> studentList;

    @GetMapping("/students")
    public List<Student> getAllStudents(){
        return List.of(new Student(1L, "Tawanda", "Banda"),
                new Student(2L, "Lorraine", "Banda"),
                new Student(3L, "Divine", "Banda"));
    }

    @GetMapping("/student")
    public Student getStudentById(){
        return new  Student(10L, "Nevson", "Chikwaku");
    }
}
