package com.example.user.config;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@EnableWebSecurity
public class ResourceServerConfig {

//    @Bean
//    public OAuth2RestOperations  restTemplate(UserInfoRestTemplateFactory factory) {
//        return factory.getUserInfoRestTemplate();
//    }
//
//    @LoadBalanced
//    @Bean
//    public OAuth2RestTemplate loadBalancedOauth2RestTemplate(
//            OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
//        return new OAuth2RestTemplate(resource, context);
//    }

    //    @Bean
//    @LoadBalanced
//    RequestInterceptor oauthFeignClient(OAuth2ClientContext oauth2ClientContext, OAuth2ProtectedResourceDetails details) {
//        return new OAuth2FeignRequestInterceptor(oauth2ClientContext, details);
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/**")
                .oauth2ResourceServer(Customizer.withDefaults());
        return http.build();
    }
}
