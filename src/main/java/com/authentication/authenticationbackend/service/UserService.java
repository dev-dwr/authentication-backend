package com.authentication.authenticationbackend.service;

import com.authentication.authenticationbackend.email.EmailSender;
import com.authentication.authenticationbackend.exception.CustomException;
import com.authentication.authenticationbackend.model.AppUserRole;
import com.authentication.authenticationbackend.model.User;
import com.authentication.authenticationbackend.payload.RegistrationCredentials;
import com.authentication.authenticationbackend.repository.UserRepository;
import com.authentication.authenticationbackend.security.JwtTokenProvider;
import com.authentication.authenticationbackend.utils.EmailBuilder;
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
    private static final String REGISTRATION_LINK = "http://localhost:8080/api/auth/confirm?token=";
    private final EmailSender emailSender;
    private final EmailBuilder emailBuilder;

    public String signin(String email, String password) {
        try {
            String token = jwtTokenProvider.createToken(email, userRepository.findUserByEmail(email).getAppUserRoles());

            boolean userEnabled = userRepository
                    .findUserByEmail(email).isEnabled();

            if(!userEnabled){
                String link = REGISTRATION_LINK + token;
                emailSender.send(email, emailBuilder.buildEmail(email, link));
                throw new IllegalStateException("email already taken or you haven't confirm your email");
            }

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            return token;
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
            newUser.setEnabled(false);

            userRepository.save(newUser);

            String token = jwtTokenProvider.createToken(credentials.getEmail(), credentials.getAppUserRoles());
            String link = REGISTRATION_LINK + token;
            emailSender.send(
                    credentials.getEmail(),
                    emailBuilder.buildEmail(credentials.getEmail(), link));

            return token;

        } else {
            throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public void delete(String email) {
        userRepository.deleteUserByEmail(email);
    }

    public User search(String email) {
        User user = userRepository.findUserByEmail(email);
        if (user == null) {
            throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
        }
        return user;
    }

    public User whoami(HttpServletRequest req) {
        return userRepository.findUserByEmail(jwtTokenProvider.getEmail(jwtTokenProvider.resolveToken(req)));
    }

    public String refreshToken(String email){
        List<AppUserRole> userRoles = userRepository.findUserByEmail(email).getAppUserRoles();
        return jwtTokenProvider.createToken(email,userRoles);
    }
    public String confirmToken(String token){
//        String token = jwtTokenProvider.resolveToken(request);
        String usersEmail = jwtTokenProvider.getEmail(token);

        User user = userRepository.findUserByEmail(usersEmail);

        if(!user.isEnabled()){
            enableAppUser(usersEmail);
        }else{
            throw new IllegalStateException("Email already confirmed");
        }

        return "confirmed";

    }
    private int enableAppUser(String email){
        return userRepository.enableAppUser(email);
    }
}
