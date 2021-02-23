package com.bizflow.auth.saml.service;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

import java.util.ArrayList;
import java.util.List;

import static com.bizflow.auth.saml.SAMLBuilder.buildSAMLObject;

public enum SLOServiceFactory {
    INSTANCE;
    public SingleLogoutService createService(String sloServcieName, String sloUri){
        SingleLogoutService sloService = buildSAMLObject(SingleLogoutService.class, SingleLogoutService.DEFAULT_ELEMENT_NAME);
        switch (sloServcieName){
            case "artifact":
                sloService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
                break;
            case "get":
                sloService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                break;
            case "post":
            default:
                sloService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        }
        sloService.setLocation(sloUri);
        return sloService;
    }
    public List<SingleLogoutService> getMultiSLOService(String[] sloServiceNames, String sloUri){
        List<SingleLogoutService> list = new ArrayList<>();
        for (String sloService :sloServiceNames) {
            list.add(createService(sloService.toLowerCase().trim(), sloUri));
        }
        return list;
    }
}
