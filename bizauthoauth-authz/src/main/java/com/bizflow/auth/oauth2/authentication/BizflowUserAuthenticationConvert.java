package com.bizflow.auth.oauth2.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.HashMap;
import java.util.Map;

public class BizflowUserAuthenticationConvert extends DefaultUserAuthenticationConverter {
    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, ?> basic = super.convertUserAuthentication(authentication);
        OzUser ozUser = (OzUser) authentication.getPrincipal();
        Map<String, Object> result = new HashMap<>(basic);

        result.put("schacHomeOrganization", ozUser.getSchacHomeOrganization());
        result.put("authenticatingAuthority", ozUser.getAuthenticatingAuthority());
        result.put("email", ozUser.getEmail());
        result.put("eduPersonPrincipalName", ozUser.getEduPersonPrincipalName());
        result.put("displayName", ozUser.getDisplayName());
        return result;
    }
}
