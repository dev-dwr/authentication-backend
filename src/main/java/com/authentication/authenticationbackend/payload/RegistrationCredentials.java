package com.authentication.authenticationbackend.payload;

import com.authentication.authenticationbackend.model.AppUserRoles;
import lombok.Data;

import java.util.List;

@Data
public class RegistrationCredentials {
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private List<AppUserRoles> appUserRoles;

}
