package com.codigo.ms_seguridad.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {

    String extractUsername(String token);
    String generateToken(UserDetails userDetails);
    String generateRefreshToken(Map<String, Object> extraClaims, UserDetails  userDetails);
    boolean validateToken(String token, UserDetails userDetails);
    boolean isRefreshToken(String token);
    
}
