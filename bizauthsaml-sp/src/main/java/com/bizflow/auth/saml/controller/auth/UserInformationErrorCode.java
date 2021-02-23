package com.bizflow.auth.saml.controller.auth;

import com.bizflow.auth.saml.error.ErrorInfo;

public enum UserInformationErrorCode implements ErrorInfo {
    TOKEN_COMMON_ERROR("TKN01A01-500"),
    TOKEN_JWT_EXPIRED_ERROR("TKN02A01-404"),
    TOKEN_JWT_VERIFY_ERROR("TKN02A02-403"),
    TRUST_KEY_EXPIRED_ERROR("TKN03A01-404"),
    TRUST_KEY_VERIFY_ERROR("TKN03A02-403")
    ;

    private final String errorCode;

    UserInformationErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    @Override
    public String getErrorCode() {
        return errorCode;
    }
}
