package com.bizflow.auth.oauth2.config;

import com.bizflow.auth.oauth2.authentication.BizflowUserAuthenticationConvert;
import com.bizflow.auth.oauth2.dao.OzUserDetailDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class AuthzServerConfigurer extends AuthorizationServerConfigurerAdapter {
    public static final String ROLE_TOKEN_CHECKER = "ROLE_TOKEN_CHECKER";
    private static final String USER_AUTHENTICATION_QUERY = "SELECT " +
            "u.loginId as username ,u.loginPasswd AS password ,u.userId as principalName " +
            ",u.deptName, u.name as displayName,u.eMail,NVL(a.authCode, 'USR') as authCode " +
            ",CASE WHEN u.lockflag = 1 THEN 'false' ELSE 'true' END AS active " +
            "FROM userobj u LEFT OUTER JOIN userauthority a ON a.userId = u.userId " +
            "WHERE loginid_cs = ? AND status <> 4";

    @Autowired
    private ApprovalStoreUserApprovalHandler approvalStoreUserApprovalHandler;
    private final ClientDetailsService clientDetailsService;
    private final DataSource dataSource;

    @Value("${oauth-server.access-token-validity-seconds}")
    private Integer accessTokenValiditySeconds;

    @Value("${oauth-server.refresh-token-validaity-seconds}")
    private Integer refreshTokenValiditySeconds;


    public AuthzServerConfigurer(DataSource dataSource, ClientDetailsService clientDetailsService) {
        this.dataSource = dataSource;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .passwordEncoder(passwordEncoder());
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(new BizflowUserAuthenticationConvert());
        endpoints
                .pathMapping("/oauth/confirm_access", "/oauth/confirm")
                .userApprovalHandler(approvalStoreUserApprovalHandler)
                .accessTokenConverter(accessTokenConverter)
                .tokenServices(tokenServices())
                .authorizationCodeServices(new JdbcAuthorizationCodeServices(this.dataSource));
    }

    private DefaultTokenServices tokenServices() {
        final DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(new AuthzJdbcTokenStore(dataSource));
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
        tokenServices.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
        return tokenServices;
    }

    @Bean
    @Autowired
    public ApprovalStoreUserApprovalHandler approvalStoreUserApprovalHandler(
            @Value("${oauth-server.approval-expiry-seconds}") Integer approvalExpirySeconds,
            ApprovalStore approvalStore,
            ClientDetailsService clientDetailsService) {
        final ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
        userApprovalHandler.setApprovalExpiryInSeconds(approvalExpirySeconds);
        userApprovalHandler.setApprovalStore(approvalStore);
        userApprovalHandler.setClientDetailsService(clientDetailsService);

        DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        userApprovalHandler.setRequestFactory(requestFactory);
        return userApprovalHandler;
    }

    @Bean
    public OzUserDetailDAO getUserDetail() {
        OzUserDetailDAO dao = new OzUserDetailDAO();
        dao.setUsersByUsernameQuery(USER_AUTHENTICATION_QUERY);
        dao.setDataSource(dataSource);
        return dao;
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }

    @Bean
    public AuthzJdbcTokenStore tokenStore() {
        return new AuthzJdbcTokenStore(dataSource);
    }

    @Bean
    public ClientDetailsService jdbcClientDetailsService() {
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder());
        return clientDetailsService;
    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
