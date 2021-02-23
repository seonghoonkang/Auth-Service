package com.bizflow.auth.saml.controller;

import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.service.ProductRequestManagerService;
import com.bizflow.auth.saml.controller.auth.UserInformationErrorCode;

public class MapperRestAPIController extends RestAPIController{

    private final ProductRequestManagerService productRequestManagerService;

    public MapperRestAPIController(ProductRequestManagerService productRequestManagerService) {
        this.productRequestManagerService = productRequestManagerService;
    }

    protected ProductRequestVO validToken(String tokenHashCode, String trustKey) throws SamlSpException {
        ProductRequestVO productRequest = productRequestManagerService.validateUser(tokenHashCode);
        if (productRequest == null) {
            throw new SamlSpException(UserInformationErrorCode.TRUST_KEY_EXPIRED_ERROR, "Token is Expired.(Not found Authentication information)");
        }
        productRequestManagerService.verifyTrust(productRequest, trustKey);
        return productRequest;
    }

}
