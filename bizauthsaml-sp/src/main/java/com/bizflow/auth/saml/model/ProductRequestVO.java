package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

@ToString
@Data
public class ProductRequestVO implements Serializable {
    private String instanceId;
    @Size(min = 16, max = 16, message = "Temporary key must be 16 characters")
    private String ivp;
    private String boomerang;
    private ProductInfoVO productInfo;
    private String authToken;
    private String aesSeed;
    private Map<String, Object> loggedInUserMetadata;
    private List<Map<String, Object>> loggedInUserLicense;
    private List<Map<String, Object>> loggedInUserGroups;
}