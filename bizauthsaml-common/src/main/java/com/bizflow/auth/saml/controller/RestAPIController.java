package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.api.model.ResponseVO;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;

public abstract class RestAPIController {

    protected <T> ResponseVO<T> makeResponseListData(HttpStatus status, List<T> body) {
        ResponseVO<T> response = new ResponseVO<>();
        response.getBody().setCount(body.size());
        response.getBody().setElements(body);
        response.getHeader().setStatus(status.value());
        return response;
    }

    protected <T> ResponseVO<T> makeResponseData(HttpStatus status, T body) {
        List<T> list = new ArrayList<>();
        list.add(body);
        return makeResponseListData(status, list);
    }

}
