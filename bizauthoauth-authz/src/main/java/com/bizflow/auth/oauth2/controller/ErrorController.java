package com.bizflow.auth.oauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestController
@RequestMapping("/error")
public class ErrorController extends AbstractErrorController {

  private final ErrorAttributes errorAttributes;

  @Autowired
  public ErrorController(ErrorAttributes errorAttributes) {
    super(errorAttributes);
    Assert.notNull(errorAttributes, "ErrorAttributes must not be null");
    this.errorAttributes = errorAttributes;
  }

  @Override
  public String getErrorPath() {
    return "/error";
  }

  @RequestMapping
  public ResponseEntity<Map<String, Object>> error(HttpServletRequest aRequest) {
    Map<String, Object> result = getErrorAttributes(aRequest, false);

    HttpStatus statusCode = INTERNAL_SERVER_ERROR;
    Object status = result.get("status");
    if (status != null && status instanceof Integer) {
      statusCode = HttpStatus.valueOf(((Integer) status).intValue());
    }
    return new ResponseEntity<>(result, statusCode);

  }

}

