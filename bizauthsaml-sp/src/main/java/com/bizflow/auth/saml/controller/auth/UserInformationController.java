package com.bizflow.auth.saml.controller.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.bizflow.auth.saml.api.model.ResponseVO;
import com.bizflow.auth.saml.controller.MapperRestAPIController;
import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.log.PerformanceLog;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.service.ProductRequestManagerService;
import com.bizflow.auth.saml.service.Signer;
import com.bizflow.auth.saml.service.TokenGenerationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/api")
public class UserInformationController extends MapperRestAPIController {
    public final TokenGenerationService tokenGenerationService;
    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Autowired
    public UserInformationController(ProductRequestManagerService productRequestManagerService,
                                     TokenGenerationService tokenGenerationService) {
        super(productRequestManagerService);
        this.tokenGenerationService = tokenGenerationService;
    }

    @GetMapping(value = {"/user-information/{tokenHashCode}"})
    public ResponseVO<Map> getUserMetadata(@PathVariable String tokenHashCode,
                                           @RequestParam(name = "trust-key") String trustKey) throws SamlSpException {
        ProductRequestVO productRequest = validToken(tokenHashCode, trustKey);
        getJWT(productRequest);
        return makeResponseData(HttpStatus.OK, productRequest.getLoggedInUserMetadata());
    }

    @GetMapping(value = {"/user-license/{tokenHashCode}"})
    public ResponseVO<Map<String, Object>> getUserLicense(@PathVariable String tokenHashCode,
                                                          @RequestParam(name = "trust-key") String trustKey) throws SamlSpException {
        ProductRequestVO productRequest = validToken(tokenHashCode, trustKey);
        getJWT(productRequest);
        return makeResponseListData(HttpStatus.OK, productRequest.getLoggedInUserLicense());
    }

    @GetMapping(value = {"/user-group/{tokenHashCode}"})
    public ResponseVO<Map<String, Object>> getUserGroup(@PathVariable String tokenHashCode,
                                                        @RequestParam(name = "trust-key") String trustKey) throws SamlSpException {
        ProductRequestVO productRequest = validToken(tokenHashCode, trustKey);
        getJWT(productRequest);
        return makeResponseListData(HttpStatus.OK, productRequest.getLoggedInUserGroups());
    }

    @PerformanceLog
    @GetMapping(value = {"/validate-token/{tokenHashCode}"})
    public ResponseVO<Map> isValidUser(@PathVariable String tokenHashCode,
                                       @RequestParam(name = "trust-key") String trustKey) throws SamlSpException {
        ProductRequestVO productRequest;
        productRequest = validToken(tokenHashCode, trustKey);
        DecodedJWT jwt = getJWT(productRequest);
        Map<String, Object> result = new HashMap<>();

        result.put("userId", productRequest.getLoggedInUserMetadata().get("id"));
        result.put("issued time of token", new Date(jwt.getExpiresAt().getTime()));
        result.put("tokenExpiredDuration", productRequest.getProductInfo().getExpiryDuration());
        result.put("tokenHashCode", tokenHashCode);
        log.debug("[validate OpenAPI] product request :: {}", result);
        return makeResponseData(HttpStatus.OK, result);
    }

    private DecodedJWT getJWT(ProductRequestVO productRequest) throws SamlSpException {
        JWTVerifier verifier = JWT.require(Signer.JWT.getHashSigner(productRequest.getProductInfo().getHaseAlg(),
                productRequest.getProductInfo().getSecurityKey()))
                .acceptExpiresAt(productRequest.getProductInfo().getExpiryDuration())
                .build();
        DecodedJWT jwt = verifier.verify(productRequest.getAuthToken());
        if (jwt == null) {
            throw new SamlSpException(UserInformationErrorCode.TOKEN_JWT_EXPIRED_ERROR, "Token is Expired. (Not found JWT token)");
        }
        return jwt;
    }
}
