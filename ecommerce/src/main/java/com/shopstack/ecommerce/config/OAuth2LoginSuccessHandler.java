package com.shopstack.ecommerce.config;

import com.shopstack.ecommerce.entity.Role;
import com.shopstack.ecommerce.entity.User;
import com.shopstack.ecommerce.repository.RoleRepository;
import com.shopstack.ecommerce.repository.UserRepository;
import com.shopstack.ecommerce.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;

    // change this to your actual frontend URL
    private static final String FRONTEND_REDIRECT_URL = "http://localhost:5173/oauth2/redirect";

    public OAuth2LoginSuccessHandler(UserRepository userRepository,
                                      RoleRepository roleRepository,
                                      JwtService jwtService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        if (email == null) {
            response.sendRedirect(FRONTEND_REDIRECT_URL + "?error=no_email_from_provider");
            return;
        }

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setName(name != null ? name : email);
            newUser.setPassword(null); // no password for OAuth2 users

            Role defaultRole = roleRepository.findByName("CUSTOMER")
                    .orElseThrow(() -> new RuntimeException("Default role CUSTOMER not found — check RoleSeeder"));
            newUser.setRole(defaultRole);

            return userRepository.save(newUser);
        });

        String token = jwtService.generateToken(user.getEmail(), user.getRole().getName());

        response.sendRedirect(FRONTEND_REDIRECT_URL + "?token=" + token);
    }
}