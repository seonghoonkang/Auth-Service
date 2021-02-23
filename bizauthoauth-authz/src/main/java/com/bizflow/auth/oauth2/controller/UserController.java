package com.bizflow.auth.oauth2.controller;

import com.bizflow.auth.oauth2.model.UserDetailVO;
import com.bizflow.auth.oauth2.service.AuthUserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
public class UserController {
    private final AuthUserService authUserService;

    public UserController(AuthUserService authUserService) {
        this.authUserService = authUserService;
    }
    @GetMapping("/user/me")
    public Principal user(HttpServletRequest request, Principal principal) {
        String t = request.getRemoteHost();
        return principal;
    }

    @GetMapping("/api/userinfo/{login-id:.+}")
    public UserDetailVO userInfo(@PathVariable("login-id") String loginId, Principal principal){
        if(loginId == null){
            loginId = principal.getName();
        }
        UserDetailVO result = authUserService.loadUserDetailByLoginId(loginId);
        return result;
    }
}
