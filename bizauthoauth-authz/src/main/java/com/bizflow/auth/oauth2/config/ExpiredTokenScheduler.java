package com.bizflow.auth.oauth2.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableScheduling
public class ExpiredTokenScheduler {

    private static final Logger LOG = LoggerFactory.getLogger(ExpiredTokenScheduler.class);

    private boolean nodeCronJobResponsible;

    private AuthzJdbcTokenStore tokenStore;

    @Autowired
    public ExpiredTokenScheduler(@Value("${cron.node-cron-job-responsible}") boolean nodeCronJobResponsible,
                                 AuthzJdbcTokenStore tokenStore) {
        this.nodeCronJobResponsible = nodeCronJobResponsible;
        this.tokenStore = tokenStore;
    }

    @Scheduled(cron = "${cron.expression}")
    public void scheduled() {
        if (nodeCronJobResponsible) {
            try {
                this.removeExpiredAccessTokens();
                this.removeExpiredRefreshTokens();
                this.removeExpiredAuthorizationCodes();
                this.removeExpiredApprovals();
            } catch (Throwable t) { //NOSONAR
                //deliberate swallowing because otherwise the scheduler stops
                LOG.error("Unexpected exception in removing expired tokens", t);
            }
        }
    }

    private int removeExpiredAccessTokens() {
        List<OAuth2AccessToken> tokens = this.tokenStore.allOAuth2AccessTokens().stream()
                .filter(token -> token.isExpired())
                .collect(Collectors.toList());
        tokens.forEach(token -> {
            this.tokenStore.removeAccessToken(token);
            LOG.info("Removed access token {} because it was expired", token.getValue());
        });
        LOG.info("Removed {} access tokens because they were expired", tokens.size());
        return tokens.size();
    }

    private int removeExpiredRefreshTokens() {
        List<ExpiringOAuth2RefreshToken> tokens = this.tokenStore.allOAuth2RefreshTokens().stream()
                .filter(token -> token.getExpiration() != null && token.getExpiration().before(new Date()))
                .collect(Collectors.toList());
        tokens.forEach(token -> {
            this.tokenStore.removeRefreshToken(token);
            LOG.info("Removed refresh token {} because it was expired", token.getValue());
        });
        LOG.info("Removed {} refresh tokens because they were expired", tokens.size());
        return tokens.size();
    }

    private int removeExpiredAuthorizationCodes() {
        int updated = this.tokenStore.removeExpiredAuthorizationCodes();
        LOG.info("Removed {} expired authorization codes", updated);
        return updated;
    }

    private int removeExpiredApprovals() {
        int updated = this.tokenStore.removeExpiredApprovals();
        LOG.info("Removed {} expired approvals", updated);
        return updated;
    }
}
