package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.model.FingerPrintSet;
import com.bizflow.auth.saml.model.RSAKeySet;
import com.bizflow.auth.saml.model.SubjectInfo;
import com.bizflow.auth.saml.service.SPManagerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SPManagerController {

    private final SPManagerService spManagerService;

    @Autowired
    public SPManagerController(SPManagerService spManagerService) {
        this.spManagerService = spManagerService;
    }

    @PostMapping(path = "/admin/createRSAKey", consumes = "application/json", produces = "application/json")
    public RSAKeySet generateRSAKeyForSP(@RequestBody SubjectInfo subjectInfo) {
        return spManagerService.generateRSAKeyForSP(subjectInfo);
    }

    @GetMapping(path = "/fingerprint")
    public FingerPrintSet getIdPCertificationFingerPrint() throws Exception {
        return spManagerService.getIdPCertificationFingerPrint();
    }
}
