package com.jwtcore.config;

import com.jwtcore.filter.JwtFilter;
import com.jwtcore.service.JwtService;
import com.jwtcore.service.JwtServiceImpl;
import com.jwtcore.util.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.userdetails.UserDetailsService;


/**
 * Auto-configuration class for JWT-related beans and security settings.
 * <p>
 * This configuration sets up necessary components like {@link JwtService}, token filters,
 * and other security-related beans required for JWT authentication.
 * <p>
 * It is loaded automatically by Spring Boot based on classpath conditions.
 */
@AutoConfiguration
@ComponentScan(basePackages = "com.jwtcore")
@ConditionalOnProperty(name = "jwt.enabled", havingValue = "true", matchIfMissing = true)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(@Value("${jwt.secret}") String jwtSecret) {
        if (jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("JWT secret key must be provided via 'jwt.secret' property");
        }
        if (jwtSecret.length() < 32) {
            throw new IllegalArgumentException("JWT secret key must be at least 32 characters long");
        }
        return new JwtUtil(jwtSecret);
    }
    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwtUtil jwtUtil) {
        return new JwtServiceImpl(jwtUtil);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtFilter jwtFilter(JwtService jwtService,UserDetailsService userDetailsService) {
        return new JwtFilter(jwtService,userDetailsService);
    }
}