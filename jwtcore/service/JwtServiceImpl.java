package com.jwtcore.service;

import com.jwtcore.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Implementation of {@link JwtService}.
 * <p>
 * Responsible for generating and validating JWT tokens.
 */

public class JwtServiceImpl extends JwtService {

    private final JwtUtil jwtUtil;


    @Autowired
    public JwtServiceImpl(JwtUtil jwtUtil){
        this.jwtUtil=jwtUtil;
    }

    @Override
    public String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authentication.getAuthorities().stream()
                .map(Object::toString)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .claims(claims)
                .subject(authentication.getName())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(jwtUtil.getDecodedKey())
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String extractedUsername = extractUsername(token);
        return extractedUsername.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtUtil.getDecodedKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenExpired(String token) {
        Date expiration = getAllClaims(token).getExpiration();
        return expiration.before(new Date(System.currentTimeMillis()));
    }

    public String extractUsername(String token) {
        return getAllClaims(token).getSubject();
    }
}
