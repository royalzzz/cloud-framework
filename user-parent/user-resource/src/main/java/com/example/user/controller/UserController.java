package com.example.user.controller;

import com.example.message.rest.MessageRest;
import com.example.user.feign.MessageFeign;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class UserController {

    @Autowired
    private MessageRest messageRest;

    @GetMapping("/user")
    public String[] getMessages() {
        return messageRest.getMessages();
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
