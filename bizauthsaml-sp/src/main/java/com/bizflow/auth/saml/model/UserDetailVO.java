package com.bizflow.auth.saml.model;

import lombok.Data;
import lombok.ToString;

@ToString
@Data
public class UserDetailVO {
    private int userId;
    private String loginId;
    private String name;
    private String empCode;
    private String deptId;
    private String deptName;
    private String titleName;
    private String pictureUrl;
    private String eMail;
    private String phone;
}
