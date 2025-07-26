package com.jwtcore.filter;

import com.jwtcore.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


/**
 * Filter responsible for validating JWT tokens.
 * <p>
 * Executes before {@link UsernamePasswordAuthenticationFilter} to ensure the token is valid.
 * If valid, the authenticated user is set in the {@link SecurityContextHolder}.
 */

public class JwtFilter extends OncePerRequestFilter {

    private JwtService jwtService;


    @Autowired
    public JwtFilter(JwtService jwtService){
        this.jwtService=jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("Jwt filter invoked");

        final String authHeader = request.getHeader("Authorization");
        final String token;
        final String username;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            String extractedUsername = null;
            try {
                extractedUsername = jwtService.extractUsername(token);
            } catch (Exception e) {
                System.err.println("JWT parsing error: " + e.getMessage());
            }

            username = extractedUsername;
            System.out.println("Username is extracted"+username);
        } else {
            token = null;
            username = null;
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtService.validateToken(token)) {

                System.out.println("Token is validated");

                final String finalToken = token;
                final String finalUsername = username;

                UserDetails userDetails = new UserDetails() {

                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        List<String> roles = jwtService.getAuthorities(finalToken);
                        return roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());
                    }

                    @Override
                    public String getPassword() {
                        return null;
                    }

                    @Override
                    public String getUsername() {
                        return finalUsername;
                    }

                    @Override
                    public boolean isAccountNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isAccountNonLocked() {
                        return true;
                    }

                    @Override
                    public boolean isCredentialsNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isEnabled() {
                        return true;
                    }
                };

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}

