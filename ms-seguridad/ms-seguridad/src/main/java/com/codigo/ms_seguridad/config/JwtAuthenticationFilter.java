package com.codigo.ms_seguridad.config;

import java.io.IOException;
import java.util.Objects;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import com.codigo.ms_seguridad.service.JwtService;
import com.codigo.ms_seguridad.service.UsuarioService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/api/authentication/v1/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
            final String tokenExtraidoHeader = request.getHeader("Authorization");
            final String tokenLimpio;
            final String username;

            if(!StringUtils.hasText(tokenExtraidoHeader)
               || !StringUtils.startsWithIgnoreCase(tokenExtraidoHeader, "Bearer ")){
                filterChain.doFilter(request,response);
                return;
            }

            tokenLimpio = tokenExtraidoHeader.substring(7);

            username = jwtService.extractUsername(tokenLimpio);


            if(Objects.nonNull(username) &&
                    SecurityContextHolder.getContext().getAuthentication() == null){

                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                UserDetails userDetails = usuarioService.userDetailsService().loadUserByUsername(username);

                if (jwtService.validateToken(tokenLimpio, userDetails) &&
                        !jwtService.isRefreshToken(tokenLimpio)){

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(authenticationToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            filterChain.doFilter(request,response);
        }
    }
