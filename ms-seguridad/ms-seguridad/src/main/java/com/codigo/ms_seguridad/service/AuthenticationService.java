package com.codigo.ms_seguridad.service;

import com.codigo.ms_seguridad.aggregates.request.SignInRefreshToken;
import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Usuario;

public interface AuthenticationService {

    Usuario signUpUser(SignUpRequest signUpRequest);
    Usuario signUpAdmin(SignUpRequest signUpRequest);

    SignInResponse signIn(SignInRequest signInRequest);
    SignInResponse getTokenByRefresh(SignInRefreshToken signInRefreshToken);;

    boolean validateToken(String token);    

}
