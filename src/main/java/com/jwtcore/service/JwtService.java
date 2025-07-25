package com.jwtcore.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;


public abstract class JwtService {


    public abstract String generateToken(Authentication authentication);

    public abstract boolean validateToken(String username);

    public abstract  String extractUsername(String token);

    protected abstract Claims getAllClaims(String token);

    protected abstract boolean isTokenExpired(String token);

     public abstract List<String> getAuthorities(String token);

}