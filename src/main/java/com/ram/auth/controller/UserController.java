package com.ram.auth.controller;

import com.ram.auth.entity.User;
import com.ram.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;
    @PostMapping(path = "/create")
    public User user(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userService.user(user);

    }
}
