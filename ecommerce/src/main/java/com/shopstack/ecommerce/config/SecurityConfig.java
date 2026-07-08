package com.shopstack.ecommerce.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Autowired
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
    "/auth/register",
    "/auth/login",
    "/login",
    "/oauth2/**"
).permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/vendor/**").hasAnyRole("VENDOR", "ADMIN")
                .requestMatchers("/warehouse/**").hasAnyRole("WAREHOUSE_STAFF", "ADMIN")
                .requestMatchers("/customer/**").hasAnyRole("CUSTOMER", "ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

            .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2LoginSuccessHandler)
            );
            // httpBasic removed — JWT filter handles auth, Basic Auth was intercepting requests

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}