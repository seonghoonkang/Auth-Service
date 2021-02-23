package com.bizflow.auth.oauth2.authentication;

import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Arrays;

@Getter
public class OzUser extends User {
    private final String eduPersonPrincipalName;
    private final String schacHomeOrganization;
    private final String displayName;
    private final String authenticatingAuthority;
    private final String email;
    private final boolean locked;


    public OzUser(String username,
                  String password,
                  String eduPersonPrincipalName,
                  String schacHomeOrganization,
                  String displayName,
                  String email,
                  String authenticatingAuthority,
                  boolean locked) {
        super(username, password, Arrays.asList(new SimpleGrantedAuthority("ROLE_TOKEN_CHECKER")));
        this.eduPersonPrincipalName = eduPersonPrincipalName;
        this.schacHomeOrganization = schacHomeOrganization;
        this.displayName = displayName;
        this.locked = locked;
        this.authenticatingAuthority = "authority::" + authenticatingAuthority;
        this.email = email;
    }
}
