package com.shopstack.ecommerce.service;

import com.shopstack.ecommerce.dto.AuthResponse;
import com.shopstack.ecommerce.dto.LoginRequest;
import com.shopstack.ecommerce.dto.RegisterRequest;
import com.shopstack.ecommerce.entity.User;
import com.shopstack.ecommerce.entity.Role;
import com.shopstack.ecommerce.repository.RoleRepository;
import com.shopstack.ecommerce.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RoleRepository roleRepository;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       RoleRepository roleRepository) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
    }

    public User register(RegisterRequest request) {

        User user = new User();

        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        String RequestedRole = request.getRole();
        if(RequestedRole == null || RequestedRole.isBlank()){
            RequestedRole = "CUSTOMER";
        }
        final String roleName = RequestedRole.toUpperCase();

        Role role = roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
        user.setRole(role);

        return userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPassword())) {

            throw new RuntimeException("Invalid password");
        }

        String token = jwtService.generateToken(user.getEmail(), user.getRole().getName());

        return new AuthResponse(token);
    }
}