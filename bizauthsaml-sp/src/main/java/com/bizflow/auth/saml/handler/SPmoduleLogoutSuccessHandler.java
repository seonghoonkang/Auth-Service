package com.bizflow.auth.saml.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SPmoduleLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private static final Logger log = LoggerFactory.getLogger(SPmoduleLogoutSuccessHandler.class);

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String boomerang = (String) request.getAttribute("boomerang");
        setDefaultTargetUrl("/sp-logout");
        request.getSession().invalidate();
        request.getSession().setAttribute("boomerang", boomerang);
        super.onLogoutSuccess(request, response, authentication);
    }

}
