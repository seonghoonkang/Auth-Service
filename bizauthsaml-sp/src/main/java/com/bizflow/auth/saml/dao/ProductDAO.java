package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.ProductInfoVO;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public interface ProductDAO {
    List<ProductInfoVO> selectProductByBaseUrl(Map<String, String> productInstanceId);
}
