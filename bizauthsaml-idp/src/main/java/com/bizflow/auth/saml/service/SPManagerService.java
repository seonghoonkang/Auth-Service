package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.model.FingerPrintSet;
import com.bizflow.auth.saml.model.RSAKeySet;
import com.bizflow.auth.saml.model.ServiceProviderVO;
import com.bizflow.auth.saml.model.SubjectInfo;

public interface SPManagerService {
    RSAKeySet generateRSAKeyForSP(SubjectInfo subject);
    FingerPrintSet getIdPCertificationFingerPrint() throws Exception;
    ServiceProviderVO getServiceProviderInfo(String acsUrl);
}
