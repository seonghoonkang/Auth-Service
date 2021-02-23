package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.dao.ProductDAO;
import com.bizflow.auth.saml.dao.SSOHistoryDAO;
import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.model.ProductInfoVO;
import com.bizflow.auth.saml.model.ProductRequestVO;
import com.bizflow.auth.saml.util.EncodeUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service("DelegationRequestService")
public class DelegationRequestService {
    protected final Logger log = LoggerFactory.getLogger(getClass());
    private final ProductDAO productDAO;
    public final SSOHistoryDAO ssoHistoryDAO;
    @Value("${sp.digest_algorithm}")
    private String aesHashAlg;

    public DelegationRequestService(ProductDAO productDAO, SSOHistoryDAO ssoHistoryDAO) {
        this.productDAO = productDAO;
        this.ssoHistoryDAO = ssoHistoryDAO;
    }

    public AuthMasterVO startBootStrap(HttpServletRequest request, ProductRequestVO productRequest) throws HttpException, IllegalAccessException {
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        if (authMaster == null) {
            authMaster = initAuthMaster(request);
        }
        addRequestToAuthMaster(request, authMaster, productRequest);
        return authMaster;
    }

    public ProductInfoVO getProductInfo(HttpServletRequest request) throws IllegalAccessException {
        Map<String, String> domainSet = extractRefererDomain(request);
        return getProductInfoVO(domainSet);
    }

    private AuthMasterVO initAuthMaster(HttpServletRequest request) {
        AuthMasterVO authMaster;
        authMaster = new AuthMasterVO();
        Map<String, ProductRequestVO> requestProductList = new ConcurrentHashMap<>();
        authMaster.setRequestProducts(requestProductList);
        authMaster.setForceAuthn(true);
        request.getSession().setAttribute("authMaster", authMaster);
        return authMaster;
    }

    private void addRequestToAuthMaster(HttpServletRequest request, AuthMasterVO authMaster, ProductRequestVO productRequest) throws HttpException, IllegalAccessException {
        Map<String, ProductRequestVO> requestProducts = authMaster.getRequestProducts();
        Map<String, String> domainSet = extractRefererDomain(request);
        String productRequestId = domainSet.values().stream()
                .filter(requestProducts::containsKey)
                .findFirst().orElse(null);

        ProductInfoVO productInfo;
        if (productRequestId == null) {
            productInfo = getProductInfoVO(domainSet);
            productRequest.setInstanceId(UUID.randomUUID().toString());
        } else {
            ProductRequestVO prevRequest = authMaster.getRequestProducts().get(productRequestId);
            productInfo = prevRequest.getProductInfo();
            productRequest.setInstanceId(prevRequest.getInstanceId());
        }
        productRequest.setProductInfo(productInfo);

        try {
            String aesSeed = EncodeUtil.toHexString(MessageDigest
                    .getInstance(aesHashAlg)
                    .digest(productInfo.getSecurityKey().getBytes(StandardCharsets.UTF_8)));
            productRequest.setAesSeed(aesSeed);
        } catch (NoSuchAlgorithmException e) {
            throw new HttpException("No such hash algorithm :: " + aesHashAlg);
        }

        authMaster.getRequestProducts().put(productInfo.getBaseUrl(), productRequest);
        authMaster.setCurrentRequestProduct(productRequest);
    }

    private Map<String, String> extractRefererDomain(HttpServletRequest request) throws IllegalAccessException {
        String domainName, subDomain = "";
        String referrer = request.getHeader("referer");
        if (StringUtils.isEmpty(referrer)) {
            throw new IllegalAccessException("Illegal Access [" + referrer + "]. This System do not allow null referrer.");
        }
        log.debug("raw Request referrer :: {}", referrer);
        try {
            URL url = new URL(referrer);
            int matchCount = StringUtils.countMatches(url.getPath(), "/");
            domainName = new URL(url.getProtocol(), url.getHost(), url.getPort(), "").toString();
            if (matchCount == 1) {
                subDomain = domainName + url.getPath();
            } else if (matchCount > 1) {
                subDomain = domainName + url.getPath().substring(0, url.getPath().indexOf("/", 1));
            }
        } catch (MalformedURLException e) {
            throw new IllegalAccessException("Malformed Request Url. The URL format is incorrect [" + referrer + "].");
        }
        Map<String, String> domainSet = new HashMap<>();
        domainSet.put("domain", domainName);
        domainSet.put("subDomain", subDomain);
        log.debug("Extracted referrer base URL :: {}", domainSet);
        return Collections.unmodifiableMap(domainSet);
    }

    private ProductInfoVO getProductInfoVO(Map<String, String> domainSet) throws IllegalAccessException {
        ProductInfoVO productInfo;
        List<ProductInfoVO> list = productDAO.selectProductByBaseUrl(domainSet);
        if (list == null || list.isEmpty()) {
            throw new IllegalAccessException("Forbidden access [" + domainSet.get("domain") + "]. This service is not registered.");
        } else if (list.size() == 1) {
            productInfo = list.get(0);
        } else {
            log.warn("*** force setup to sub-domain name. We are not support sub-domain name with domain name. ===> {}", domainSet);
            //noinspection OptionalGetWithoutIsPresent
            productInfo = list.stream()
                    .filter(e ->
                            e.getBaseUrl().equals(domainSet.get("subDomain")))
                    .findFirst()
                    .get();
        }
        return productInfo;
    }

}
