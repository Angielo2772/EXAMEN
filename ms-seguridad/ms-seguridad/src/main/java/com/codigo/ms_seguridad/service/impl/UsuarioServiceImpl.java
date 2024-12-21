package com.codigo.ms_seguridad.service.impl;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.repository.UsuarioRepository;
import com.codigo.ms_seguridad.service.UsuarioService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UsuarioServiceImpl implements UsuarioService{

    private final UsuarioRepository usuarioRepository;

    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return usuarioRepository.findByUsername(username).orElseThrow(
                    () -> new UsernameNotFoundException("Usuario no encontrado en base de datos"));
            }
        };
    }

    @Override
    public Usuario findUserByUsername(String username) {
        return usuarioRepository.findByUsername(username).orElseThrow(
            () -> new UsernameNotFoundException("Usuario no encontrado en base de datos"));
    }

}
