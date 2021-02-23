package com.bizflow.auth.saml.error;

import com.bizflow.auth.saml.api.model.ResponseVO;
import com.bizflow.auth.saml.controller.RestAPIController;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice("com.bizflow.auth.saml.controller.auth")
public class SamlSpExceptionHandler extends RestAPIController {

    @ExceptionHandler(SamlSpException.class)
    public ResponseVO<Map> exceptionAdvice(HttpServletResponse response, SamlSpException samlSpException) {
        Map<String, Object> errorMessage = new HashMap<>();
        int statusCode = samlSpException.getErrorInfo().getResponseCode();
        errorMessage.put("errCode", samlSpException.getErrorInfo().getCode());
        errorMessage.put("errMessage", samlSpException.getMessage());
        response.setStatus(statusCode);
        return makeResponseData(HttpStatus.valueOf(statusCode), errorMessage);
    }
}
