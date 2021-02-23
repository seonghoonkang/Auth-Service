package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.service.MetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MetadataController {

  final MetadataService metadataService;

  @Autowired
  public MetadataController(MetadataService metadataService) {
    this.metadataService = metadataService;
  }

  @RequestMapping(method = RequestMethod.GET, value = "/metadata", produces = "application/xml")
  public String metadata() throws Exception {
    return metadataService.createMetadata();
  }

}
