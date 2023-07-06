package com.example.auth.provider;

import com.example.auth.token.PhonePasswordAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PhonePasswordProvider implements AuthenticationProvider {

    private PasswordEncoder passwordEncoder;
    private UserDetailsService authUserLoginService;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    private final Log logger = LogFactory.getLog(this.getClass());
//    private static final Logger providerLogger = LoggerFactory.getLogger(PhonePasswordProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        UserDetails loadedUser = authUserLoginService.loadUserByUsername(authentication.getPrincipal().toString());

        if (loadedUser == null) {
            throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");
        }
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//            if (!presentedPassword.equals(userDetails.getPassword())) {
        if (!encoder.matches(authentication.getCredentials().toString(), loadedUser.getPassword())) {
//        if (!authentication.getCredentials().toString().equals(loadedUser.getPassword())) {
//            providerLogger.info("Credentials:{}, password:{}", authentication.getCredentials().toString(), loadedUser.getPassword());
//        if (!passwordEncoder.matches(authentication.getCredentials().toString(), loadedUser.getPassword())) {
            throw new BadCredentialsException("手机号或密码错误");
        }

        PhonePasswordAuthenticationToken result = new PhonePasswordAuthenticationToken(loadedUser, authentication.getCredentials(), this.authoritiesMapper.mapAuthorities(loadedUser.getAuthorities()));
        result.setDetails(authentication.getDetails());
//        providerLogger.debug("Authenticated user");
        return result;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return PhonePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public UserDetailsService getAuthUserLoginService() {
        return authUserLoginService;
    }
    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }
    public void setAuthUserLoginService(UserDetailsService authUserLoginService) {
        this.authUserLoginService = authUserLoginService;
    }

}
