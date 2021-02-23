package com.bizflow.auth.saml.service;

import com.auth0.jwt.JWT;
import com.bizflow.auth.saml.controller.auth.BpmProxyErrorCode;
import com.bizflow.auth.saml.controller.auth.UserInformationErrorCode;
import com.bizflow.auth.saml.dao.BizFlowBaseApi;
import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.model.BPMSessionInfoVO;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.util.SecurityCipher;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service("TokenGenerationService")
public class TokenGenerationService {
    @Value("${sp.base_url}")
    private String spModuleBaseUrl;
    @Value("${sp.myIP}")
    private String myIP;
    @Value("${sp.bpm_host}")
    private String bpmHost;
    @Value("${sp.bpm_port}")
    private int bpmPort;
    @Value("${sp.bpm_cert_filename}")
    private String bpmCertFilename;

    protected final Logger log = LoggerFactory.getLogger(getClass());
    private final ProductRequestManagerService manager;

    public TokenGenerationService(ProductRequestManagerService manager) {
        this.manager = manager;
    }

    public Map<String, String> getCallbackValue(HttpServletRequest request) {
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        setAuthInfoWithBpm(authMaster);
        setAuthToken(authMaster);
        Map<String, String> responseParam = new HashMap<>();
        ProductRequestVO productRequest = authMaster.getCurrentRequestProduct();

        String landingPage = productRequest.getProductInfo().getBaseUrl() + productRequest.getProductInfo().getLandingPage();

        String encToken = encryptTokenWithAES(productRequest);

        responseParam.put("encAuthToken", encToken);
        responseParam.put("landingPage", landingPage);
        responseParam.put("boomerang", productRequest.getBoomerang());
        manager.saveRequestRepository(request, encToken, authMaster);
        return responseParam;
    }

    private String encryptTokenWithAES(ProductRequestVO productRequest) throws SamlSpException {
        SecurityCipher cipher = SecurityCipher.getInstance();
//-- TODO: You can used AES256 when jdk version is Java8u161 and higher :: https://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size
        cipher.setKey256(productRequest.getAesSeed());
        cipher.setInitVector(productRequest.getIvp());
        log.debug("productRequest AesSeed :: **[{}]**", productRequest.getAesSeed());
        log.debug("productRequest IVP :: **[{}]**", productRequest.getIvp());

        String encAuthToken;
        try {
            encAuthToken = cipher.encipher256Base64(productRequest.getAuthToken());
        } catch (Exception e) {
            SamlSpException sse = new SamlSpException(e, UserInformationErrorCode.TOKEN_COMMON_ERROR);
            sse.setMessage("Failure to encrypt token. There is message :: " + e.getMessage());
            throw sse;
        }
        log.debug("aes encrypt token ===> {}", encAuthToken);
        return encAuthToken;
    }

    private void setAuthInfoWithBpm(AuthMasterVO authMaster) throws SamlSpException {
        //-- TODO: need to refactoring
        ProductRequestVO currentProductRequest = authMaster.getCurrentRequestProduct();
        BPMSessionInfoVO bpmSessionInfo = authMaster.getBpmSessionInfo();
        if (bpmSessionInfo == null) {
            bpmSessionInfo = getBpmSessionInfoVO(authMaster);
        }

        String bpmUserAuthentication;
        String bpmUserLicense;
        String bpmUserGroups;
        try {
            bpmUserAuthentication = BizFlowBaseApi.getUserInfoToJson(bpmSessionInfo);
            bpmUserLicense = BizFlowBaseApi.getLicenseGroupsToJson(bpmSessionInfo);
            bpmUserGroups = BizFlowBaseApi.getUserGroupToJson(bpmSessionInfo);
        } catch (Exception e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_COMMON_ERROR, "Failure to get user Information from BPM. There is message :: " + e.getMessage());
        }

        ObjectMapper mapper = new ObjectMapper();
        List<String> userAttrListForProduct = currentProductRequest.getProductInfo().getUserAttributeList();
        List<Map<String, Object>> bpmUserMetadata, authList, groupList;

        try {
            bpmUserMetadata = mapper.readValue(bpmUserAuthentication, new TypeReference<List<Map<String, Object>>>(){});
            authList = mapper.readValue(bpmUserLicense, new TypeReference<List<Map<String, Object>>>() {});
            groupList = mapper.readValue(bpmUserGroups, new TypeReference<List<Map<String, Object>>>() {});
       } catch (IOException e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_DATA_MAPPING_ERROR, "Failure bind mapper");
        }

        if(bpmUserMetadata == null){
            throw new SamlSpException(BpmProxyErrorCode.BPM_DATA_BINDING_ERROR, "Do not bind Empty Data to bpm user metadata");
        }

        Map<String, Object> selectedUserMetadata = bpmUserMetadata.get(0).entrySet().stream()
                .filter(e -> userAttrListForProduct.contains(e.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        currentProductRequest.setLoggedInUserMetadata(selectedUserMetadata);
        log.debug(String.valueOf(selectedUserMetadata));

        currentProductRequest.setLoggedInUserLicense(authList);
        log.debug(String.valueOf(authList));

        currentProductRequest.setLoggedInUserGroups(groupList);
        log.debug(String.valueOf(groupList));
    }

    private BPMSessionInfoVO getBpmSessionInfoVO(AuthMasterVO authMaster) {
        BPMSessionInfoVO bpmSessionInfo;
        try {
            String loginInfoXML;
            loginInfoXML = BizFlowBaseApi.loginBySso(bpmHost, bpmPort, myIP, authMaster.getAuthenticationId(),
                    ResourceUtils.getFile(bpmCertFilename));
            bpmSessionInfo = new BPMSessionInfoVO(BizFlowBaseApi.createHWSessionInfo(loginInfoXML));
            authMaster.setBpmSessionInfo(bpmSessionInfo);
        } catch (FileNotFoundException e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_CERTIFICATION_ERROR, "Can not found your certification file. Check cert file.");
        } catch (Exception e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_CONNECTION_ERROR, "Failure BPM login by SSO. There is message :: " + e.getMessage());
        }
        return bpmSessionInfo;
    }

    private void setAuthToken(AuthMasterVO authMaster) throws SamlSpException {
        ProductRequestVO currentProductRequest = authMaster.getCurrentRequestProduct();
        String authToken;
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", currentProductRequest.getProductInfo().getHaseAlg());
        ObjectMapper oMapper = new ObjectMapper();
        Map bpmSessionInfoMap = oMapper.convertValue(authMaster.getBpmSessionInfo(), Map.class);
        try {
            authToken = JWT.create()
                    .withHeader(header)
                    .withIssuer(spModuleBaseUrl + "/launcher.html")
                    .withExpiresAt(DateTime.now(DateTimeZone.UTC).toDate())
                    .withAudience(currentProductRequest.getProductInfo().getBaseUrl())
                    .withJWTId(SecurityCipher.getInstance().generateHexStringKey())
                    .withClaim("userInfo", currentProductRequest.getLoggedInUserMetadata())
                    .withClaim("userAuthList", currentProductRequest.getLoggedInUserLicense())
                    .withClaim("userGroupList", currentProductRequest.getLoggedInUserGroups())
                    .withClaim("bpmSessionInfo", bpmSessionInfoMap)
                    .sign(Signer.JWT.getHashSigner(currentProductRequest.getProductInfo().getHaseAlg(),
                            currentProductRequest.getProductInfo().getSecurityKey()));
        } catch (Exception e) {
            throw new SamlSpException(UserInformationErrorCode.TOKEN_COMMON_ERROR, "Failure to create JWT Token. There is message :: " + e.getMessage());
        }
        currentProductRequest.setAuthToken(authToken);
    }
}
