package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.controller.auth.UserInformationErrorCode;
import com.bizflow.auth.saml.dao.SSOHistoryDAO;
import com.bizflow.auth.saml.dao.UserDetailDAO;
import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.model.LoginHistoryVO;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.model.UserDetailVO;
import com.bizflow.auth.saml.util.SecurityCipher;
import com.bizflow.auth.saml.util.UserAgentUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service("ProductRequestManagerService")
public class ProductRequestManagerService {
    protected final Logger log = LoggerFactory.getLogger(getClass());
    private static final Map<String, ProductRequestVO> requestRepository = new ConcurrentHashMap<>();
    private static final int OTP_COUNTER = 30;
    private final UserDetailDAO userDetailDAO;
    private final SSOHistoryDAO ssoHistoryDAO;

    public ProductRequestManagerService(UserDetailDAO userDetailDAO, SSOHistoryDAO ssoHistoryDAO) {
        this.userDetailDAO = userDetailDAO;
        this.ssoHistoryDAO = ssoHistoryDAO;
    }

    public void verifyTrust(ProductRequestVO currentProductRequest, String trustKey) throws SamlSpException {
        SecurityCipher cipher = SecurityCipher.getInstance();
        cipher.setKey256(currentProductRequest.getAesSeed());
        boolean trust = false;
        long secondCut = Instant.now().getEpochSecond();
        for(int i = 0; i < OTP_COUNTER; i++ ){
            long otp = (secondCut - i)*1000000;
            cipher.setInitVector(Long.toString(otp));
            log.debug("Initial Vector ===> {}", cipher.getInitVector());
            try {
                String securityKey = cipher.decipher256Base64(trustKey);
                if(currentProductRequest.getProductInfo().getSecurityKey().equals(securityKey)){
                    log.debug("find otp ===> {}", otp);
                    trust = true; break;
                }
            } catch (Exception e) {
                log.error(e.getMessage());
                throw new SamlSpException(UserInformationErrorCode.TRUST_KEY_VERIFY_ERROR, "Failure Decipher trust key.");
            }
        }
        if(!trust){
            throw new SamlSpException(UserInformationErrorCode.TRUST_KEY_VERIFY_ERROR, "Can not trust key.");
        }
        cipher.setInitVector(currentProductRequest.getIvp());
    }

    @Async
    public void saveRequestRepository(HttpServletRequest httpRequest, String encToken, AuthMasterVO authMaster){
        ProductRequestVO productRequest = authMaster.getCurrentRequestProduct();
        requestRepository.putIfAbsent(digestHexMessage(encToken), productRequest);
        saveLoginSuccessToHistory(httpRequest,authMaster);
    }

    public ProductRequestVO validateUser(String hexToken){
        return requestRepository.get(hexToken);
    }

    public String digestHexMessage(String originMessage){
        long beforeTime = System.currentTimeMillis(); //코드 실행 전에 시간 받아오기
        StringBuilder stringBuffer = new StringBuilder();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(originMessage.getBytes());

            for (byte bytes : messageDigest.digest()) {
                stringBuffer.append(String.format("%02x", bytes & 0xff));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        long afterTime = System.currentTimeMillis(); // 코드 실행 후에 시간 받아오기
        log.debug("Convert spend time of Hex message (m) : {} ", (afterTime - beforeTime)/1000);
        return stringBuffer.toString();
    }

    private void saveLoginSuccessToHistory(HttpServletRequest request, AuthMasterVO authMaster) {
        int userId = -1;
        ProductRequestVO productRequest = authMaster.getCurrentRequestProduct();
        UserDetailVO user = userDetailDAO.selectUserDetail(authMaster.getAuthenticationId());
        if(user != null){
            userId = user.getUserId();
        }
        LoginHistoryVO loginHistory = LoginHistoryVO.builder()
                .userId(userId)
                .userName(authMaster.getAuthenticationId())
                .actionTitle("LOGIN_SUCCESS")
                .actionStatus("1")
                .ipAddr(UserAgentUtil.getUserAgentIP(request))
                .detail("LOGGED IN Product  :: " + productRequest.getProductInfo().getProductName()
                        + ", Access UserAgent ::" + request.getHeader("User-Agent"))
                .build();
        ObjectMapper mapper = new ObjectMapper();

        Map params = mapper.convertValue(loginHistory, Map.class);
        //noinspection unchecked
        params.put("instanceId", productRequest.getInstanceId());
        //noinspection unchecked
        ssoHistoryDAO.updateLoginHistory(params);
    }

}
