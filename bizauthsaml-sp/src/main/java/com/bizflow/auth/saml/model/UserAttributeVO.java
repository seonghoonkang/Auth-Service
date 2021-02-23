package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class UserAttributeVO {
    private int id;
    private String attrId;
    private String attrDesc;
}
