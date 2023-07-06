package com.example.auth.filter;

import com.example.auth.token.PhonePasswordAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

public class PhonePasswordFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/loginByPhonePassword", "POST");

    public PhonePasswordFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String phoneNumber = this.obtainPhone(request);
            phoneNumber = phoneNumber != null ? phoneNumber : "";
            phoneNumber = phoneNumber.replace(" ", "").trim();
            String password = this.obtainPassword(request);
            password = password != null ? password : "";
            PhonePasswordAuthenticationToken authRequest = new PhonePasswordAuthenticationToken(phoneNumber, password);
            authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }

    @Nullable
    protected String obtainPassword(HttpServletRequest request) {
        String passwordParameter = "password";
        return request.getParameter(passwordParameter);
    }

    @Nullable
    protected String obtainPhone(HttpServletRequest request) {
        String phoneParameter = "phone";
        return request.getParameter(phoneParameter);
    }

}
