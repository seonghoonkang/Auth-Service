package com.bizflow.auth.saml.service;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleSignOnService;

import java.util.ArrayList;
import java.util.List;

import static com.bizflow.auth.saml.SAMLBuilder.buildSAMLObject;

public enum SSOServiceFactory {
    INSTANCE;

    public SingleSignOnService createService(String ssoServiceName, String ssoLocation){
        SingleSignOnService ssoService = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        switch (ssoServiceName){
            case "artifact":
                ssoService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
                break;
            case "get":
                ssoService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                break;
            case "post":
            default:
                ssoService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        }
        ssoService.setLocation(ssoLocation);
        return ssoService;
    }

    public List<SingleSignOnService> getMultiSSOService(String[] ssoServiceNames, String ssoLocation){
        List<SingleSignOnService> list = new ArrayList<>();
        for (String ssoService :ssoServiceNames) {
            list.add(createService(ssoService.toLowerCase().trim(), ssoLocation));
        }
        return list;
    }
}
