package com.authentication.authenticationbackend.service;

import com.authentication.authenticationbackend.exception.CustomException;
import com.authentication.authenticationbackend.model.AppUserRole;
import com.authentication.authenticationbackend.model.User;
import com.authentication.authenticationbackend.payload.RegistrationCredentials;
import com.authentication.authenticationbackend.repository.UserRepository;
import com.authentication.authenticationbackend.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;


@Service
@RequiredArgsConstructor
public class UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;


    public String signin(String email, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            return jwtTokenProvider.createToken(email, userRepository.findUserByEmail(email).getAppUserRoles());
        } catch (AuthenticationException e) {
            throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public String signup(RegistrationCredentials credentials) {
        if (!userRepository.existsByEmail(credentials.getEmail())) {
            User newUser = new User();
            newUser.setEmail(credentials.getEmail());
            newUser.setFirstname(credentials.getFirstname());
            newUser.setLastname(credentials.getLastname());
            newUser.setPassword(passwordEncoder.encode(credentials.getPassword()));
            newUser.setCreatedAt(Instant.now());

            userRepository.save(newUser);
            return jwtTokenProvider.createToken(credentials.getEmail(), credentials.getAppUserRoles());

        } else {
            throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public User whoami(HttpServletRequest req) {
        return userRepository.findUserByEmail(jwtTokenProvider.getEmail(jwtTokenProvider.resolveToken(req)));
    }

    public String refreshToken(String email){
        List<AppUserRole> userRoles = userRepository.findUserByEmail(email).getAppUserRoles();
        return jwtTokenProvider.createToken(email,userRoles);
    }
}
