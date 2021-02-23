package com.bizflow.auth.oauth2.config;

import com.bizflow.auth.oauth2.authentication.OzAuthenticationManager;
import com.bizflow.auth.oauth2.filter.CorsFilter;
import com.bizflow.auth.oauth2.filter.OZAuthenticationFilter;
import com.bizflow.auth.oauth2.provider.OZAuthenticationProvider;
import com.bizflow.auth.oauth2.service.OzUserDetailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.resource.PathResourceResolver;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;

@Configuration
@EnableWebSecurity
@EnableWebMvc
@ComponentScan(basePackages = {"com.bizflow.auth.oauth2"})
public class AuthzServerWebConfigurer implements WebMvcConfigurer {
    private static final Logger LOG = LoggerFactory.getLogger(AuthzServerWebConfigurer.class);

    @Bean
    public FilterRegistrationBean lenientCorsFilter() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(new CorsFilter());
        return filterRegistrationBean;
    }

    @Bean
    public LocaleResolver localeResolver() {
        CookieLocaleResolver slr = new CookieLocaleResolver();
        slr.setDefaultLocale(Locale.ENGLISH);
        return slr;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }

    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {

        configurer.defaultContentType(MediaType.valueOf("application/json"), MediaType.valueOf("application/xml"));
        configurer.favorParameter(false).favorPathExtension(false);
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/res/**")
                .addResourceLocations("classpath:/public/").setCachePeriod(3600)
                .resourceChain(true)
                .addResolver(new PathResourceResolver());
    }

    @Order(1)
    @Configuration
    public static class AuthenticationSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Value("${oauth-server.username}")
        private String ozUserName;

        @Value("${oauth-server.password}")
        private String ozUserPassword;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/deprovision/**")
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .csrf()
                    .disable()
                    .addFilterBefore(
                            new BasicAuthenticationFilter(
                                    new OzAuthenticationManager(ozUserName, ozUserPassword)
                            ), BasicAuthenticationFilter.class
                    )
                    .authorizeRequests()
                    .antMatchers("/deprovision/**").hasRole("USER")
            ;
        }

    }

    @Configuration
    @Order(2)
    public static class GeneralSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        private final Environment environment;
        private final OzUserDetailService ozUserDetailService;
        private final PasswordEncoder passwordEncoder;

        public GeneralSecurityConfigurationAdapter(Environment environment,
                                                   OzUserDetailService ozUserDetailService,
                                                   @Qualifier("passwordEncoder") PasswordEncoder passwordEncoder) {
            this.environment = environment;
            this.ozUserDetailService = ozUserDetailService;
            this.passwordEncoder = passwordEncoder;
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web
                    .ignoring()
                    .antMatchers("/static/**")
                    .antMatchers("/info")
                    .antMatchers("/health");
//            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                    .and()
                    .requestMatchers()
                    .antMatchers("/login", "/oauth/authorize", "/logout")
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().permitAll()
                    .loginPage("/login")
                    .and()
                    .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            ;
        }

        @Autowired
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            OZAuthenticationProvider provider = new OZAuthenticationProvider(ozUserDetailService, passwordEncoder);
            auth.authenticationProvider(provider);
        }

        @Bean
        public OZAuthenticationFilter authenticationFilter() throws Exception {
            OZAuthenticationFilter filter = new OZAuthenticationFilter();
            filter.setAuthenticationFailureHandler(new LoginFailureHandler("/login?error=true"));
            filter.setAuthenticationManager(authenticationManager());
            return filter;
        }

        private static class LoginFailureHandler implements AuthenticationFailureHandler {
            private final String url;
            public LoginFailureHandler(String url) {
                this.url = url;
            }

            @Override
            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                LOG.error("Login Failure. {}", e.getMessage());
            }
        }
    }
}
