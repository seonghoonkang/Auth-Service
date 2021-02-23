package com.bizflow.auth.saml.error;

public enum CommonErrorCode implements ErrorInfo {
    SERVER_ERROR("CMN01A01-500");

    private final String errorCode;

    CommonErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    @Override
    public String getErrorCode() {
        return errorCode;
    }
}
