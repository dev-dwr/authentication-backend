package com.authentication.authenticationbackend.controller;

import com.authentication.authenticationbackend.model.User;
import com.authentication.authenticationbackend.payload.LoginCredentials;
import com.authentication.authenticationbackend.payload.RegistrationCredentials;
import com.authentication.authenticationbackend.service.UserService;
import io.swagger.annotations.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@Slf4j
@CrossOrigin("*")
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserService userService;

    @ApiOperation(value = "${UserController.signin}")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 422, message = "Invalid username/password supplied")})
    @PostMapping("/login")
    public String login(@RequestBody LoginCredentials loginCredentials) {
        return userService.signin(loginCredentials.getEmail(), loginCredentials.getPassword());
    }

    @ApiOperation(value = "${UserController.signup}")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 422, message = "Username is already in use")})
    @PostMapping("/register")
    public String signup(@RequestBody RegistrationCredentials credentials) {
        return userService.signup(credentials);
    }


    @GetMapping( "/me")
    @PreAuthorize("hasRole('ROLE_STUDENT') or hasRole('ROLE_TEACHER')")
    @ApiOperation(value = "${UserController.me}", response = User.class, authorizations = { @Authorization(value="apiKey") })
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public User whoami(HttpServletRequest req) {
        return userService.whoami(req);
    }

    @DeleteMapping( "/{email}")
    @PreAuthorize("hasRole('ROLE_TEACHER')")
    @ApiOperation(value = "${UserController.delete}", authorizations = { @Authorization(value="apiKey") })
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 404, message = "The user doesn't exist"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public String delete(@ApiParam("Email") @PathVariable String email) {
        userService.delete(email);
        return email;
    }

    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ROLE_TEACHER')")
    @ApiOperation(value = "${UserController.search}", response = User.class, authorizations = { @Authorization(value="apiKey") })
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "Something went wrong"),
            @ApiResponse(code = 403, message = "Access denied"),
            @ApiResponse(code = 404, message = "The user doesn't exist"),
            @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public User search(@ApiParam("Email") @PathVariable String email) {
        return userService.search(email);
    }

    @GetMapping("/refresh")
    @PreAuthorize("hasRole('ROLE_TEACHER') or hasRole('ROLE_STUDENT')")
    public String refresh(HttpServletRequest req) {
        log.info("Refresh Token method. Login of User = " + req.getRemoteUser());
        return userService.refreshToken(req.getRemoteUser());
    }

    @GetMapping("/confirm")
    public String confirm(@RequestParam("token") String token){
        return userService.confirmToken(token);
    }

    @GetMapping("/secured")
    public String secured() {
        return "secured";
    }
}
