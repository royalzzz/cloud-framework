package com.example.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

import static com.example.auth.utils.CodeUtils.base64UrlEncode;
import static com.example.auth.utils.CodeUtils.sha256;

@RestController
@RequestMapping("code")
public class CodeController {

    @GetMapping("callback")
    public Map<String, Object> callback(String code) {
        Map<String, Object> map = new HashMap<>();
        map.put("code", code);
        return map;
    }

    @GetMapping("encode")
    public String encode(String code_verifier) {
        return base64UrlEncode(code_verifier);
    }
}
