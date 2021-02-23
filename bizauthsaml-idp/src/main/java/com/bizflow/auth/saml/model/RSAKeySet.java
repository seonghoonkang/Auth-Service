package com.bizflow.auth.saml.model;

import lombok.Data;

@Data
public class RSAKeySet {
    private String privateKeyPEM;
    private String certificationPEM;
}
