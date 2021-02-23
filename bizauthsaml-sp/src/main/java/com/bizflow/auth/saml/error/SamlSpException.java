package com.bizflow.auth.saml.error;

import lombok.Getter;

@Getter
public class SamlSpException extends RuntimeException{
    private ErrorInfo errorInfo;
    private String message;

    public SamlSpException(ErrorInfo errorInfo, String message) {
        super();
        this.errorInfo = errorInfo;
        this.message = message;
    }
    public SamlSpException(Throwable e, ErrorInfo errorInfo) {
        super(e);
        this.errorInfo = errorInfo;
    }

    public void setMessage(String message){
        this.message = message;
    }
}
