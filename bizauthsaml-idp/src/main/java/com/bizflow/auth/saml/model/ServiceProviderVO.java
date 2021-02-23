package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

import java.util.Date;

@ToString
@Data
public class ServiceProviderVO {
    private int spSeq;
    private String entityId;
    private String metaUrl;
    private String acsUrl;
    private String sloUrl;
    private Date validUntil;
    private int status;
    private int countdownLatch;
    private int updUserId;
    private Date updDateTime;
//    private String privKey;
//    private String certKey;
    private String spDesc;
    private String orgName;
    private String orgUnitName;
    private String localName;
    private String country;
    private String email;
}
