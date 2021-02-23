package com.bizflow.auth.oauth2.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OZLogoutSuccessHandler implements org.springframework.security.web.authentication.logout.LogoutSuccessHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OZLogoutSuccessHandler.class);

    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        LOG.debug("logout success");
    }
}
