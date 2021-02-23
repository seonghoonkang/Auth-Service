package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.api.SharedConfiguration;
import com.bizflow.auth.saml.api.SharedController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
public class OTPController extends SharedController {
    public OTPController(SharedConfiguration configuration) {
        super(configuration);
    }

    @GetMapping(value = {"/epoch-second"})
    public String getEpochSecond(){
        long epochSecond = Instant.now().getEpochSecond();
        return Long.toString(epochSecond*1000000);
    }
}
