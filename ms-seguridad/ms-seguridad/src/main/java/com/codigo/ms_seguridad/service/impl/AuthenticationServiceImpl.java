package com.codigo.ms_seguridad.service.impl;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.codigo.ms_seguridad.aggregates.constants.Constants;
import com.codigo.ms_seguridad.aggregates.request.SignInRefreshToken;
import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Rol;
import com.codigo.ms_seguridad.entity.Role;
import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.repository.RolRepository;
import com.codigo.ms_seguridad.repository.UsuarioRepository;
import com.codigo.ms_seguridad.service.AuthenticationService;
import com.codigo.ms_seguridad.service.JwtService;
import com.codigo.ms_seguridad.service.UsuarioService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService{
    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    @Override
    public Usuario signUpUser(SignUpRequest signUpRequest) {
        Usuario usuario = getUsuarioEntity(signUpRequest);
        usuario.setRoles(Collections.singleton(getRoles(Role.USER)));
        return usuarioRepository.save(usuario);
    }

    private Usuario getUsuarioEntity(SignUpRequest signUpRequest){
        return Usuario.builder()
                .nombres(signUpRequest.getNombres())
                .apellidos(signUpRequest.getApellidos())
                .username(signUpRequest.getUsername())
                .password(new BCryptPasswordEncoder().encode(signUpRequest.getPassword()))
                .isAccountNonExpired(Constants.STATUS_ACTIVE)
                .isAccountNonLocked(Constants.STATUS_ACTIVE)
                .isCredentialsNonExpired(Constants.STATUS_ACTIVE)
                .isEnabled(Constants.STATUS_ACTIVE)
                .build();
    }

    @Override
    public Usuario signUpAdmin(SignUpRequest signUpRequest) {
        Usuario usuario = getUsuarioEntity(signUpRequest);
        Set<Rol> roles = new HashSet<>();
        roles.add(getRoles(Role.USER));
        roles.add(getRoles(Role.ADMIN));
        usuario.setRoles(roles);
        return usuarioRepository.save(usuario);
    }

    @Override
    public SignInResponse signIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getUsername(),signInRequest.getPassword()));
        var user = usuarioRepository.findByUsername(signInRequest.getUsername()).orElseThrow(
                () -> new UsernameNotFoundException("Error Usuario no encontrado en base de datos"));
        var token = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
        return SignInResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public SignInResponse getTokenByRefresh(SignInRefreshToken signInRefreshToken) {
        if (!jwtService.isRefreshToken(signInRefreshToken.getRefreshToken())){
            throw new RuntimeException("ERROR EL TOKEN INGRESADO NO ES: TYPE : REFRESH");
        }

        String username = jwtService.extractUsername(signInRefreshToken.getRefreshToken());

        Usuario usuario = usuarioRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("No se encontro al usuario"));
    
        if(!jwtService.validateToken(signInRefreshToken.getRefreshToken(), usuario)){
            throw  new RuntimeException("Error el token no le pertenece al usuario");
        }

        String newToken = jwtService.generateToken(usuario);

        return SignInResponse.builder()
                .token(newToken)
                .refreshToken(signInRefreshToken.getRefreshToken())
                .build();
    }

    @Override
    public boolean validateToken(String token) {
        final String jwt;
        final String username;

        if(Objects.nonNull(token) && !token.trim().isEmpty()){
           jwt = token.substring(7);
           username = jwtService.extractUsername(jwt);
           if(Objects.nonNull(username) && !username.trim().isEmpty()){
               UserDetails userDetails = usuarioService
                       .userDetailsService()
                       .loadUserByUsername(username);
               return jwtService.validateToken(jwt, userDetails);
           }
        }
        return false;
    }

    private Rol getRoles(Role rolBuscado){
        return rolRepository.findByNombreRol(rolBuscado.name())
            .orElseThrow(
                () -> new RuntimeException("ERROR EL ROL NO EXISTE :" + rolBuscado.name()));
    }

}
