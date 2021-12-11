package com.authentication.authenticationbackend.repository;

import com.authentication.authenticationbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    Boolean existsByEmail(String email);
    User findUserByEmail(String email);
}
