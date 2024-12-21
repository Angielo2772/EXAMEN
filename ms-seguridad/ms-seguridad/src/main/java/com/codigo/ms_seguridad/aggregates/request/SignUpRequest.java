package com.codigo.ms_seguridad.aggregates.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpRequest {

    private String nombres;
    private String apellidos;
    private String username;
    private String password;
    
}
