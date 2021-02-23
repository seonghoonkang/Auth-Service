package com.bizflow.auth.saml.api.model;

import lombok.Data;

@Data
public class ResponseVO<T>  {
    private ResponseHeaderVO header = new ResponseHeaderVO();
    private ResponseBodyVO<T> body = new ResponseBodyVO<>();
}
