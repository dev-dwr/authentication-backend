package com.authentication.authenticationbackend.email;

public interface EmailSender {
    void send(String to, String email);
}
