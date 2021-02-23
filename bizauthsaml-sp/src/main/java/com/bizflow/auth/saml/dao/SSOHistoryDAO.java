package com.bizflow.auth.saml.dao;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Repository
@Transactional
public interface SSOHistoryDAO {
    int insertLoginHistory(Map<String, Object> params);
    int updateLoginHistory(Map<String, Object> params);
}
