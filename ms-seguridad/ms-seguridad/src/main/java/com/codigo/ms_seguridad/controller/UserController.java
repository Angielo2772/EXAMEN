package com.codigo.ms_seguridad.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.service.UsuarioService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/user/v1/")
@RequiredArgsConstructor
public class UserController {

    private final UsuarioService usuarioService;

    @GetMapping("users/{username}")
    public ResponseEntity<Usuario> findUserByUsername(@PathVariable String username) {
        return ResponseEntity.ok(usuarioService.findUserByUsername(username));
    }
}
