package com.shopstack.ecommerce.controller;

import com.shopstack.ecommerce.dto.AuthResponse;
import com.shopstack.ecommerce.dto.LoginRequest;
import com.shopstack.ecommerce.dto.RegisterRequest;
import com.shopstack.ecommerce.entity.User;
import com.shopstack.ecommerce.service.AuthService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public User register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @GetMapping("/me")
    public Authentication me(Authentication authentication) {
        return authentication;
    }
}