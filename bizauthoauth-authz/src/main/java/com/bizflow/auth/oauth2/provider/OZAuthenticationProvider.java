package com.bizflow.auth.oauth2.provider;

import com.bizflow.auth.oauth2.authentication.OzUser;
import com.bizflow.auth.oauth2.service.OzUserDetailService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class OZAuthenticationProvider implements AuthenticationProvider {
    private final OzUserDetailService ozUserDetailService;
    private final PasswordEncoder passwordEncoder;

    public OZAuthenticationProvider(OzUserDetailService ozUserDetailService, PasswordEncoder passwordEncoder) {
        this.ozUserDetailService = ozUserDetailService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        String loginId = (String) token.getPrincipal();
        String password = (String) token.getCredentials();
        OzUser loginUser = (OzUser) ozUserDetailService.loadUserByUsername(loginId);
        if (!passwordEncoder.matches(password, loginUser.getPassword())) {
            throw new BadCredentialsException(loginUser.getUsername() + "Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(loginUser, password, loginUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
