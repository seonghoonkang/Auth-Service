package com.bizflow.auth.oauth2.config;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class AuthzJdbcTokenStore extends JdbcTokenStore {
    private final NamedParameterJdbcTemplate jdbcTemplate;
    public AuthzJdbcTokenStore(DataSource dataSource) {
        super(dataSource);
        this.jdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }

    @Override
    public void removeAccessToken(String tokenValue) {
        try {
            super.removeAccessToken(tokenValue);
        } catch (RuntimeException e) {
            //try once more
            super.removeAccessToken(tokenValue);
        }

    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        try {
            super.storeAccessToken(token, authentication);
        } catch (DuplicateKeyException e) {
            //-- TODO: See=> https://github.com/spring-projects/spring-security-oauth/issues/1242
        }
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return super.getAccessToken(authentication);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        return super.findTokensByClientIdAndUserName(clientId, userName);
    }

    List<OAuth2AccessToken> allOAuth2AccessTokens() {
        return jdbcTemplate.query("select token from oauth_access_token",
                (rs, rowNum) -> deserializeAccessToken(rs.getBytes(1)));
    }

    List<ExpiringOAuth2RefreshToken> allOAuth2RefreshTokens() {
        return jdbcTemplate.query("select token from oauth_refresh_token",
                (rs, rowNum) -> deserializeRefreshToken(rs.getBytes(1))).stream()
                .filter(refreshToken -> refreshToken instanceof ExpiringOAuth2RefreshToken)
                .map(ExpiringOAuth2RefreshToken.class::cast)
                .collect(Collectors.toList());
    }

    int removeExpiredAuthorizationCodes() {
        return this.jdbcTemplate.update("DELETE FROM oauth_code WHERE created <= (SYSDATE + 10/(24*60))",
                Collections.EMPTY_MAP);
    }

    int removeExpiredApprovals() {
        return this.jdbcTemplate.update("DELETE FROM oauth_approvals WHERE expiresAt <= SYSDATE",
                Collections.EMPTY_MAP);
    }

}
