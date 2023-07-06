package com.example.auth.filter;

import com.example.auth.token.PhoneVerificationCodeAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

public class PhoneVerificationCodeFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/loginByPhoneVerificationCode", "POST");

    public PhoneVerificationCodeFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {
        if (!httpServletRequest.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + httpServletRequest.getMethod());
        } else {
            String phone = httpServletRequest.getParameter("phone");
            phone = phone.replace(" ", "").trim();
            String code = httpServletRequest.getParameter("code");
            code = code != null ? code : "";
            code = code.trim();
            PhoneVerificationCodeAuthenticationToken authRequest = new PhoneVerificationCodeAuthenticationToken(phone, code);
            authRequest.setDetails(this.authenticationDetailsSource.buildDetails(httpServletRequest));
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }
}
