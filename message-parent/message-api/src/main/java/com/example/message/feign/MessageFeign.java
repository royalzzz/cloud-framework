package com.example.message.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(url = "http://127.0.0.1:7002", contextId = "message")
public interface MessageFeign {

    @GetMapping("/message")
    String[] getMessage();

}
