package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;
import org.joda.time.LocalDateTime;

import java.io.Serializable;
import java.util.Map;

@Data
@ToString
public class AuthMasterVO implements Serializable {
    private Map<String, ProductRequestVO> requestProducts;
    private String authenticationId;
    private ProductRequestVO currentRequestProduct;
    private BPMSessionInfoVO bpmSessionInfo;
    private boolean forceAuthn;
    public static final LocalDateTime creationDate = LocalDateTime.now();
}
