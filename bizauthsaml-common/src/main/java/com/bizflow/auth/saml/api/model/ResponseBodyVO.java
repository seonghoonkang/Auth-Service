package com.bizflow.auth.saml.api.model;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ResponseBodyVO<T> {
    private int count = 0;
    private List<T> elements = new ArrayList<>();
}
