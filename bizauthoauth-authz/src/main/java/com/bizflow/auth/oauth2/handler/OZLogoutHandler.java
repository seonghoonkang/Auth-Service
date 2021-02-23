package com.bizflow.auth.oauth2.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OZLogoutHandler implements LogoutHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OZLogoutHandler.class);

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        LOG.debug("Logout!");
    }
}
