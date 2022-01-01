package com.authentication.authenticationbackend.repository;

import com.authentication.authenticationbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import javax.transaction.Transactional;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Boolean existsByEmail(String email);
    Optional<User> findUserByEmail(String email);
    User deleteUserByEmail(String email);
    Optional<User> findById(Long id);
    @Transactional
    @Modifying
    @Query("UPDATE User u " + "SET u.enabled = TRUE " + "WHERE u.email = ?1")
    int enableAppUser(String email);
}
