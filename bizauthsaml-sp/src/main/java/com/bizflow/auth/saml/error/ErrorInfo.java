package com.bizflow.auth.saml.error;

public interface ErrorInfo {

    String getErrorCode();

    default String getCode() {
        return this.getErrorCode().split("-")[0];
    }

    default int getResponseCode() {
        return Integer.parseInt(this.getErrorCode().split("-")[1]);
    }
}
