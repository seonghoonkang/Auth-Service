package com.bizflow.auth.oauth2.service;

import com.bizflow.auth.oauth2.dao.OzUserDetailDAO;
import com.bizflow.auth.oauth2.model.UserDetailVO;
import org.springframework.stereotype.Service;

@Service
public class AuthUserService {
    private final OzUserDetailDAO userDetailDAO;

    public AuthUserService(OzUserDetailDAO userDetailDAO) {
        this.userDetailDAO = userDetailDAO;
    }

    public UserDetailVO loadUserDetailByLoginId(String loginId){
        return userDetailDAO.loadRegisteredUserByUserId(loginId).get(0);
    }
}
