package com.bizflow.auth.saml.model;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@Builder
public class LoginHistoryVO {
    private int userId;
    private String userName;
    private String ipAddr;
    private String detail;
    private String actionTitle;
    private String actionStatus;
}
