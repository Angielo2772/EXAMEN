package com.codigo.ms_seguridad.aggregates.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignInRequest {

    private String username;
    private String password;
    
}
