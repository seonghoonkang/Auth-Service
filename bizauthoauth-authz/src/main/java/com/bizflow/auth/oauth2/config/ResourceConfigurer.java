package com.bizflow.auth.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;

@Configuration
@EnableResourceServer
public class ResourceConfigurer extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.anonymous().disable()
                .authorizeRequests()
                .antMatchers("/user/me").access("#oauth2.hasScope('read:user')")
                .antMatchers(HttpMethod.GET, "/api/**").access("#oauth2.hasScope('view:user-detail')")
                .and()
                .exceptionHandling()
                .accessDeniedHandler(new OAuth2AccessDeniedHandler())
        ;
    }

}
