package com.bizflow.auth.oauth2.service;

import com.bizflow.auth.oauth2.dao.OzUserDetailDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;

@Service
public class OzUserDetailService implements UserDetailsService  {
    private final PasswordEncoder passwordEncoder;
    private final OzUserDetailDAO userDetailDAO;

    @Autowired
    public OzUserDetailService(PasswordEncoder passwordEncoder, OzUserDetailDAO userDetailDAO) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailDAO = userDetailDAO;
    }
    @PostConstruct
    public void init(){

    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDetailDAO.loadUserByUsername(username);
    }

}
