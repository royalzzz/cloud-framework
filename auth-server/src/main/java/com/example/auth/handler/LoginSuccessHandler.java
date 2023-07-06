package com.example.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;
import java.util.function.Consumer;

public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final static Logger logger = LoggerFactory.getLogger(LoginSuccessHandler.class);
    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
    };

    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        logger.info("{} Login {}", authentication.getName(), authentication.getDetails());
        httpServletResponse.getWriter().write("{\"message\": \"登录成功\"}");
//        if (authentication instanceof OAuth2AuthenticationToken) {
//            if (authentication.getPrincipal() instanceof OidcUser) {
//                this.oidcUserHandler.accept((OidcUser) authentication.getPrincipal());
//            } else if (authentication.getPrincipal() != null) {
//                this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
//            }
//        }
//
//        this.delegate.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
    }
}
