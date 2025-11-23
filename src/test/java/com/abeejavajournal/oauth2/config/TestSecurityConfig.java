package com.abeejavajournal.oauth2.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@TestConfiguration
public class TestSecurityConfig {
    @Bean
    @Primary
    public JwtDecoder jwtDecoder() {
        return token -> {
            throw new IllegalStateException(
                "This JwtDecoder should not be called during tests. " +
                "Use Spring Security Test's jwt() request post processor instead."
            );
        };
    }
}
