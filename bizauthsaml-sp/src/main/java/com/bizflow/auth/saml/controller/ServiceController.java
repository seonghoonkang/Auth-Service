package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.SAMLPrincipal;
import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.model.ProductInfoVO;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.service.DelegationRequestService;
import com.bizflow.auth.saml.service.TokenGenerationService;
import org.apache.http.HttpException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@Controller
public class ServiceController {

    private final TokenGenerationService tokenGenerationService;
    private final DelegationRequestService delegationRequestService;
//    protected final Logger LOG = LoggerFactory.getLogger(getClass());

    public ServiceController(TokenGenerationService tokenGenerationService, DelegationRequestService authRequestManageService) {
        this.tokenGenerationService = tokenGenerationService;
        this.delegationRequestService = authRequestManageService;
    }

    //The problem is that when we use application/x-www-form-urlencoded, Spring doesn't understand it as a RequestBody.
    // So, if we want to use this we must remove the @RequestBody annotation.
    @PostMapping("/")
    public String index(HttpServletRequest request, @Valid ProductRequestVO productRequest, Authentication authentication, ModelMap modelMap) throws HttpException, IllegalAccessException {
        AuthMasterVO authMaster = delegationRequestService.startBootStrap(request, productRequest);
        Map<String, Object> respParam = new HashMap<>();
        respParam.put("forceAuthn", authMaster.isForceAuthn());
        modelMap.addAttribute("model", respParam);
        authMaster.setForceAuthn(false);
        return authentication == null ? "index" : "redirect:/launcher";
    }

    @PostMapping({"launcher", "/launcher.html"})
    public String postLauncher(HttpServletRequest request, Authentication authentication, ModelMap modelMap)
            throws HttpException {
        return launcher(request, authentication, modelMap);
    }

    @GetMapping({"launcher", "/launcher.html"})
    public String getLauncher(HttpServletRequest request, Authentication authentication, ModelMap modelMap)
            throws HttpException {
        return launcher(request, authentication, modelMap);
    }

    private String launcher(HttpServletRequest request, Authentication authentication, ModelMap modelMap) throws HttpException {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new HttpException("Session Expired. Unknown user authentication information.");
        }

        Map<String, String> respParam = new HashMap<>();
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        authMaster.setAuthenticationId(((SAMLPrincipal) authentication.getPrincipal()).getNameID());
        modelMap.addAttribute("myService", tokenGenerationService.getCallbackValue(request));

        request.changeSessionId();
        return "launcher";
    }

    @GetMapping("/sp-logout")
    public String logoutGet(HttpServletRequest request, ModelMap modelMap) throws IllegalAccessException {
        return doLogout(request, modelMap);
    }

    private String doLogout(HttpServletRequest request, ModelMap modelMap) throws IllegalAccessException {
        if (request.getHeader("referer") == null) {
            return "logout";
        }
        Map<String, Object> respParam = new HashMap<>();
        String boomerang = (String) request.getSession().getAttribute("boomerang");
        ProductInfoVO productInfo = delegationRequestService.getProductInfo(request);
        StringBuilder logoutUrl = new StringBuilder();
        logoutUrl.append(productInfo.getBaseUrl()).append(productInfo.getLogoutUrl());
        if(boomerang != null){
            logoutUrl.append("?boomerang=").append(boomerang);
        }
        respParam.put("logoutUrl", logoutUrl);
        modelMap.addAttribute("model", respParam);
        return "jumper";
    }
}
