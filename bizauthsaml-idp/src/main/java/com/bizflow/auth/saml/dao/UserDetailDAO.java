package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.UserDetailVO;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.List;

@Repository
public interface UserDetailDAO {
    List<UserDetailVO> selectUserList(HashMap<String, String> params);
}
