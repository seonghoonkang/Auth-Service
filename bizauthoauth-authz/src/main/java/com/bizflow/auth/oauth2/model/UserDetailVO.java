package com.bizflow.auth.oauth2.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

import java.io.Serializable;

@ToString
@AllArgsConstructor
@Data
public class UserDetailVO implements Serializable {
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
    private String dob;
    private boolean isActive;
}
