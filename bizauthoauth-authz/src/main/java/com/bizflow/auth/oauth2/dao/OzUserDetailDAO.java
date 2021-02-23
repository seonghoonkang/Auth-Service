package com.bizflow.auth.oauth2.dao;

import com.bizflow.auth.oauth2.authentication.OzUser;
import com.bizflow.auth.oauth2.model.UserDetailVO;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;

import java.util.List;

public class OzUserDetailDAO extends JdbcDaoImpl {
    private static final String USER_DETAIL_QUERY =
            "SELECT u.userId, u.name, u.empCode, u.deptId, u.deptName,(SELECT titleName " +
                    "FROM title a WHERE a.titleId = u.titleId) AS titleName, " +
                    "'http://image.server.org/img/user-picture.jpg' AS userPicture, " +
                    "u.eMail, u.phone, u.dob, " +
                    "CASE WHEN u.lockflag = 1 THEN 'false' ELSE 'true' END AS active " +
                    "FROM userobj u WHERE loginid_cs = ? AND status <> 4";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<UserDetails> users = loadUsersByUsername(username);
        if (users.size() == 0) {
            throw new UsernameNotFoundException("User not found :: " + username);
        }
        //-- TODO: Implementation multiple Authorization Code
        return users.get(0);
    }

    @Override
    protected List<UserDetails> loadUsersByUsername(String username) {
        String query = getUsersByUsernameQuery();
        return getJdbcTemplate().query(query, new String[]{username}, (rs, i) -> {
            String username1 = rs.getString(1);
            String password = rs.getString(2);
            String principalName = rs.getString(3);
            String orgName = rs.getString(4);
            String displayName = rs.getString(5);
            String email = rs.getString(6);
            String auth = rs.getString(7);
            boolean locked = Boolean.parseBoolean(rs.getString(8));
            return new OzUser(username1, password, principalName, orgName, displayName, email, auth, locked);
        });
    }

    public List<UserDetailVO> loadRegisteredUserByUserId(String loginId) {
        return this.getJdbcTemplate().query(this.USER_DETAIL_QUERY, new String[]{loginId}, (rs, rowNum) -> {
            int userId = rs.getBigDecimal(1).intValue();
            String name = rs.getString(2);
            String empCode = rs.getString(3);
            String deptId = rs.getString(4);
            String deptName = rs.getString(5);
            String titleName = rs.getString(6);
            String pictureUrl = rs.getString(7);
            String eMail = rs.getString(8);
            String phone = rs.getString(9);
            String dob = rs.getString(10);
            boolean status = Boolean.parseBoolean(rs.getString(11));
            UserDetailVO user = new UserDetailVO(userId, loginId, name, empCode, deptId, deptName, titleName, pictureUrl, eMail, phone, dob, status);
            return user;
        });
    }
}