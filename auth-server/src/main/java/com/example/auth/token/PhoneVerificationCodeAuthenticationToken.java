package com.example.auth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class PhoneVerificationCodeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    public PhoneVerificationCodeAuthenticationToken(Object phonePrincipal, Object codeCredential) {
        super(null);
        this.principal = phonePrincipal;
        this.credentials = codeCredential;
        super.setAuthenticated(false);
    }

    public PhoneVerificationCodeAuthenticationToken(Object phonePrincipal, Object codeCredential, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = phonePrincipal;
        this.credentials = codeCredential;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }

    @Override
    public String toString() {
        return "SmsAuthenticationToken{" +
                "principal=" + principal +
                ", credentials=" + credentials +
                '}';
    }
}
