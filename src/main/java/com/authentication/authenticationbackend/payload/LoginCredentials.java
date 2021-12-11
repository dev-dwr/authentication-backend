package com.authentication.authenticationbackend.payload;

import lombok.Getter;

@Getter
public class LoginCredentials {
    private String email;
    private String password;
}
