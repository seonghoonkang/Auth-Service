package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.ServiceProviderVO;
import org.springframework.stereotype.Repository;

@Repository
public interface ServiceProviderDAO {
    ServiceProviderVO selectServiceProviderWithId(String entityId);
}
