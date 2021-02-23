package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;
import java.util.List;

@Data
@ToString
public class ProductInfoVO implements Serializable {
    private int id;
    private String productId;
    private String productName;
    private String baseUrl;
    private String landingPage;
    private String securityKey;
    private String logoutUrl;
    private String version;
    private String haseAlg;
    private boolean isActive;
    private int expiryDuration;
    private List<String> userAttributeList;
}
