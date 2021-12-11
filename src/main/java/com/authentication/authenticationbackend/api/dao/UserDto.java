package com.authentication.authenticationbackend.api.dao;

import com.authentication.authenticationbackend.model.AppUserRole;
import lombok.Data;


import java.util.List;

@Data
public class UserDto {
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    List<AppUserRole> appUserRoles;
}
