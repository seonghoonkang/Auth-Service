package com.bizflow.auth.oauth2.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

public class OzAuthenticationManager implements AuthenticationManager {

    private String username;
    private String password;


    public OzAuthenticationManager(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = String.class.cast(authentication.getPrincipal());
        if (!name.equals(username)) {
            throw new UsernameNotFoundException("Unknown user: " + name);
        }
        if (!authentication.getCredentials().equals(password)) {
            throw new BadCredentialsException("Bad credentials");
        }
        return new UsernamePasswordAuthenticationToken(
                name,
                authentication.getCredentials(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    }

}
