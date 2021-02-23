package com.bizflow.auth.saml.controller.auth;

import com.bizflow.auth.saml.error.ErrorInfo;

public enum BpmProxyErrorCode implements ErrorInfo {
    BPM_COMMON_ERROR("BPM01A01-500"),
    BPM_CONNECTION_ERROR("BPM02A01-500"),
    BPM_CERTIFICATION_ERROR("BPM03A01-404"),
    BPM_DATA_BINDING_ERROR("BPM04A01-500"),
    BPM_DATA_MAPPING_ERROR("BPM04A02-500")
    ;

    private final String errorCode;

    BpmProxyErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    @Override
    public String getErrorCode() {
        return errorCode;
    }
}
