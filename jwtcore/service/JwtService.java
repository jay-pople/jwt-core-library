package com.jwtcore.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;


public abstract class JwtService {


    public abstract String generateToken(Authentication authentication);

    public abstract boolean validateToken(String username,UserDetails userDetails);

    public abstract  String extractUsername(String token);

    protected abstract Claims getAllClaims(String token);

    protected abstract boolean isTokenExpired(String token);

}