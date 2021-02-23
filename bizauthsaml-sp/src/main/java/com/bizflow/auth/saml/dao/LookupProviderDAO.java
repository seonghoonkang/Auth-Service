package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.LookupProviderVO;
import org.springframework.stereotype.Repository;

@Repository
public interface LookupProviderDAO {
    LookupProviderVO selectLookup(String lType);
}
