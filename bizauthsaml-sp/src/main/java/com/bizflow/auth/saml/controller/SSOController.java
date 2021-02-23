package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.api.SharedController;
import com.bizflow.auth.saml.config.SSOConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api", consumes = "application/json")
public class SSOController extends SharedController {

    @Autowired
    public SSOController(final SSOConfigurer configuration) {
        super(configuration);
    }

    @PutMapping(value = {"/ssoServiceURL"})
    public void setSsoServiceURL(@RequestBody String ssoServiceURL) {
        LOG.info("Request to set ssoServiceURL to {}", ssoServiceURL);
        configuration().setIdpSSOServiceURL(ssoServiceURL);
    }

    @PutMapping("/protocolBinding")
    public void setProtocolBinding(@RequestBody String protocolBinding) {
        LOG.info("Request to set protocolBinding to {}", protocolBinding);
        configuration().setProtocolBinding(protocolBinding);
    }

    @PutMapping("/assertionConsumerServiceURL")
    public void setAssertionConsumerServiceURL(@RequestBody String assertionConsumerServiceURL) {
        configuration().setAssertionConsumerServiceURL(assertionConsumerServiceURL);
    }

    private SSOConfigurer configuration() {
        return (SSOConfigurer) super.configuration;
    }

}
