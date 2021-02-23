package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

@ToString
@Data
public class LookupProviderVO {
    private int seq;
    private String lType;
    private String id;
    private String name;
    private String label;
    private int dispOrder;
}
