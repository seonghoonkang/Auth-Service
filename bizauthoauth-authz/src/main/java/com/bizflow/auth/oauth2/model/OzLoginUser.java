package com.bizflow.auth.oauth2.model;

import lombok.Data;

@Data
public class OzLoginUser {
    private String userId;
    private String loginId;
    private String password;
    private String name;
    private String empCode;
    private String deptId;
    private String deptName;
    private String titleName;
    private String pictureUrl;
    private String eMail;
    private String phone;
    private String dob;
    private String authCode;
    private boolean active;
}
