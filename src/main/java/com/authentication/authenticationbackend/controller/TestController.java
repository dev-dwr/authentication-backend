package com.authentication.authenticationbackend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @GetMapping("/")
    public String test(){
        return "main";
    }


    @GetMapping( "/restricted")
    public Principal user(Principal principal) {
        return principal;
    }
}
