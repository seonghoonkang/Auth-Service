package com.bizflow.auth.saml.model;

import lombok.Data;

@Data
public class FingerPrintSet {
    private String SHA256FingerPrint;
    private String SHA1FingerPrint;
}
