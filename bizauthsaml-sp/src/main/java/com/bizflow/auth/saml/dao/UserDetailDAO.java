package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.UserDetailVO;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface UserDetailDAO {
    UserDetailVO selectUserDetail(@Param("userId") String loginId);
}
