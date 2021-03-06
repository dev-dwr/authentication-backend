package com.authentication.authenticationbackend.model;

import org.springframework.security.core.GrantedAuthority;

public enum AppUserRoles implements GrantedAuthority {
    ROLE_STUDENT, ROLE_TEACHER, ROLE_USER;

    public String getAuthority() {
        return name();
    }
}
