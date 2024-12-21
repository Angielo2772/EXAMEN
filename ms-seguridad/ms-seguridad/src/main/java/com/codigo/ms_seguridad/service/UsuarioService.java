package com.codigo.ms_seguridad.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.codigo.ms_seguridad.entity.Usuario;

public interface UsuarioService {

    UserDetailsService userDetailsService();
    Usuario findUserByUsername(String username);

}
