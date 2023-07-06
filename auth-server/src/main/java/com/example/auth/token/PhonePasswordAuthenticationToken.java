package com.example.auth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class PhonePasswordAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;
    private final Object credentials;

    public PhonePasswordAuthenticationToken() {
        super(null);
        this.principal = null;
        this.credentials = null;
        super.setAuthenticated(false);
    }

    public PhonePasswordAuthenticationToken(Object phonePrincipal, Object passwordCredential) {
        super(null);
        this.principal = phonePrincipal;
        this.credentials = passwordCredential;
        super.setAuthenticated(false);
    }

    public PhonePasswordAuthenticationToken(Object phonePrincipal, Object passwordCredential, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = phonePrincipal;
        this.credentials = passwordCredential;
        super.setAuthenticated(true);
    }

    public PhonePasswordAuthenticationToken(Object details, boolean authenticated, Object phonePrincipal, Object passwordCredential, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = phonePrincipal;
        this.credentials = passwordCredential;
        this.setDetails(details);
        super.setAuthenticated(authenticated);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
