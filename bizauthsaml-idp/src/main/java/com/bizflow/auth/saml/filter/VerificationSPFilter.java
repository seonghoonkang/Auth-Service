package com.bizflow.auth.saml.filter;

import com.bizflow.auth.saml.handler.SAMLMessageHandler;
import com.bizflow.auth.saml.model.ServiceProviderVO;
import com.bizflow.auth.saml.service.SPManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

public class VerificationSPFilter extends OncePerRequestFilter {
    private static final int PENDING = 1;
    private static final int ACTIVE = 2;
    private static final int DISABLED = 3;

    protected final Log logger = LogFactory.getLog(getClass());
    private final SAMLMessageHandler samlMessageHandler;
    private final ApplicationContext applicationContext;

    public VerificationSPFilter(ApplicationContext applicationContext, SAMLMessageHandler samlMessageHandler) {
        this.samlMessageHandler = samlMessageHandler;
        this.applicationContext = applicationContext;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String servletPath = request.getServletPath();
        if (servletPath == null || !servletPath.endsWith("sign-on") || !isSAMLRequest(request)) {
            chain.doFilter(request, response);
            return;
        }
        try {

            SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, request.getMethod().equalsIgnoreCase("POST"));
            AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
            String requestAcsUrl = authnRequest.getAssertionConsumerServiceURL();
            logger.debug("=======> Got a ACS URL --> " + requestAcsUrl);

            SPManagerService service = applicationContext.getBean(SPManagerService.class);
            ServiceProviderVO spInfo = service.getServiceProviderInfo(requestAcsUrl);

            if (spInfo == null) {
                //-- TODO Should be make to Processed Exception as a below Code.
                throw new IllegalAccessException("Unknown Service Provider. Please Registration Service Provider.");
            }

            if (spInfo.getStatus() != ACTIVE) {
                logger.debug("=======> spInfo acsUrl() => " + spInfo.toString());
                throw new IllegalAccessException("Verification failed for Service Provider. Please contact Administrator.");
            }

        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

        chain.doFilter(request, response);
    }

    private boolean isSAMLRequest(HttpServletRequest request){
        if(request.getMethod().equalsIgnoreCase("POST"))
            return true;
        Enumeration<String> names = request.getParameterNames();
        while ( names.hasMoreElements()){
            String name = names.nextElement();
            if(!name.contains("SAMLRequest")){
                return true;
            }
        }
        return false;
    }
}
