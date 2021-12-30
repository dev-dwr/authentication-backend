package com.authentication.authenticationbackend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @GetMapping("/")
    public Principal test(Principal principal){
        System.out.println("Main" + principal.getName());
        return principal;
    }


    @GetMapping( "/restricted")
    public Principal user(Principal principal) {
        return principal;
    }
}
