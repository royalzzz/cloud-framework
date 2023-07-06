package com.example.auth.token;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "@class")
@JsonIgnoreProperties(ignoreUnknown = true)
public class PhonePasswordAuthenticationTokenMixin {

    @JsonCreator
    public PhonePasswordAuthenticationTokenMixin(
            @JsonProperty("principal") Object principal,
            @JsonProperty("credentials") Object credentials,
            @JsonProperty("authorities") Collection<GrantedAuthority> authorities,
            @JsonProperty("details") Object details,
            @JsonProperty("authenticated") boolean authenticated) {
    }

}
