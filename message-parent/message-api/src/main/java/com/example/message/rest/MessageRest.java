package com.example.message.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class MessageRest {

    @Autowired
    private RestTemplate restTemplate;

    public String[] getMessages() {
        return restTemplate.getForObject("http://127.0.0.1:7002/message", String[].class);
    }
}
