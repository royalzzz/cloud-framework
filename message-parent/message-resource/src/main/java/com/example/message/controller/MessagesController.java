package com.example.message.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessagesController {

    @GetMapping("/message")
    public String[] getMessages() {
        return new String[]{"Message 1", "Message 2", "Message 3"};
    }

    @GetMapping("/jwt")
    public Object getJWT(@AuthenticationPrincipal Jwt principal) {
        return principal;
    }

    @GetMapping("/auth")
    public Object getAuth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
