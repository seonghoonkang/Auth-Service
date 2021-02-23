package com.bizflow.auth.oauth2.controller;

import com.bizflow.auth.oauth2.authentication.OzUser;
import com.bizflow.auth.oauth2.config.AuthzJdbcTokenStore;
import com.bizflow.auth.oauth2.service.OzUserDetailService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class AuthenticationController {
    private final OzUserDetailService userService;
    private AuthzJdbcTokenStore tokenStore;
    private ClientDetailsService clientDetailsService;
    public AuthenticationController(OzUserDetailService userService, AuthzJdbcTokenStore tokenStore,
                                    ClientDetailsService clientDetailsService) {
        this.userService = userService;
        this.tokenStore = tokenStore;
        this.clientDetailsService = clientDetailsService;
    }

    @GetMapping("/")
    public String index(Authentication authentication) {
        return authentication == null ? "index" : "redirect:/user/me";
    }

    @GetMapping("/login")
    public String login(ModelMap modelMap) {
        return "login";
    }

    @GetMapping("/logout")
    public String logoutPOST(@RequestParam(name = "client-id") String clientId,
                             ModelMap modelMap, HttpServletRequest request, Authentication authentication) {
        modelMap.addAttribute("clientId", clientId);
        return doLogout(modelMap, request, (OzUser) authentication.getPrincipal());
    }

    private String doLogout(ModelMap modelMap, HttpServletRequest request, OzUser ozUser) {
        if (request.getHeader("referer") == null) {
            return "logout";
        }
        String clientId = (String) modelMap.get("clientId");
        Map<String, Object> respParam = new HashMap<>();
        List<OAuth2AccessToken> tokens = tokenStore
                .findTokensByClientIdAndUserName(clientId, ozUser.getUsername())
                .stream().collect(Collectors.toList())
        ;
        tokenStore.removeAccessToken(tokens.get(0));
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        String logoutUrl = (String) clientDetails.getAdditionalInformation().get("logout_url");
        if(logoutUrl == null){
            logoutUrl = request.getHeader("referer");
        }
        respParam.put("logoutUrl", logoutUrl);
        modelMap.addAttribute("model", respParam);
        request.getSession().invalidate();
        SecurityContextHolder.getContext().setAuthentication(null);
        return "jumper";
    }

}
