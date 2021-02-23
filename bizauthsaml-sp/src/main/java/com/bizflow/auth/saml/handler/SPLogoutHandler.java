package com.bizflow.auth.saml.handler;

import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.model.ProductInfoVO;
import com.bizflow.auth.saml.model.ProductRequestVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

public class SPLogoutHandler implements LogoutHandler {
    protected final Logger LOG = LoggerFactory.getLogger(getClass());

    @Override
    public void logout(HttpServletRequest req, HttpServletResponse res, Authentication authentication) {
        AuthMasterVO authMaster = (AuthMasterVO) req.getSession().getAttribute("authMaster");
        if (authMaster != null) {
            Map<String, ProductRequestVO> loginRequest = authMaster.getRequestProducts();
            String boomerang = (String) authMaster.getCurrentRequestProduct().getBoomerang();
            req.setAttribute("boomerang", boomerang);
            for (Map.Entry<String, ProductRequestVO> entry : loginRequest.entrySet()) {
                ProductInfoVO info = entry.getValue().getProductInfo();
                LOG.debug("request Id :: {}, logout URL :: {}{}", entry.getKey(), info.getBaseUrl(), info.getLogoutUrl());
            }
        }
    }
}
