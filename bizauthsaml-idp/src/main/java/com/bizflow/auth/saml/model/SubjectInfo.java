package com.bizflow.auth.saml.model;

import lombok.Data;

@Data
public class SubjectInfo {
    private String entityId;
    private String unit;
    private String organization;
    private String local;
    private String country;
    private String email;
}