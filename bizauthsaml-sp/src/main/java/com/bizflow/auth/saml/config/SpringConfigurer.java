package com.bizflow.auth.saml.config;

import com.bizflow.auth.saml.KeyStoreLocator;
import com.bizflow.auth.saml.ProxiedSAMLContextProviderLB;
import com.bizflow.auth.saml.filter.DefaultMetadataDisplayFilter;
import com.bizflow.auth.saml.handler.SPAccessDeniedHanlder;
import com.bizflow.auth.saml.handler.SPLogoutHandler;
import com.bizflow.auth.saml.handler.SPmoduleLogoutSuccessHandler;
import com.bizflow.auth.saml.provider.ResourceMetadataProvider;
import com.bizflow.auth.saml.provider.RoleSAMLAuthenticationProvider;
import com.bizflow.auth.saml.service.DefaultSAMLUserDetailsService;
import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.Filter;
import javax.servlet.SessionCookieConfig;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Timer;

@Configuration
@ComponentScan(basePackages = {"com.bizflow.auth.saml"})
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SpringConfigurer extends WebSecurityConfigurerAdapter {
    @Value("${sp.idp_metadata_url}")
    private String identityProviderMetadataUrl;
    @Value("${sp.acs_location_path}")
    private String assertionConsumerServiceURLPath;
    @Value("${sp.entity_id}")
    private String spEntityId;
    @Value("${sp.base_url}")
    private String spBaseUrl;
    @Value("${sp.passphrase}")
    private String spPassphrase;
    @Value("${sp.private_key}")
    private String spPrivateKey;
    @Value("${sp.certificate}")
    private String spCertificate;
    @Value("${secure_cookie}")
    private boolean secureCookie;
    @Value("${server.servlet.context-path}")
    private String contextPath;

    private final String sessionName = "ss-uuid";
    private final DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/health", "/info");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) {
        builder.authenticationProvider(samlAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement().sessionFixation().changeSessionId()
                .and()
                .csrf().disable()
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/test", "/metadata", "/favicon.ico", "/*.css", "/epoch-second", "/sp.js", "/errors/**", assertionConsumerServiceURLPath + "/**").permitAll()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADM")
                .anyRequest().hasAnyRole("USR", "ADM")
                .and()
                .httpBasic()
                .authenticationEntryPoint(samlEntryPoint())
                .and()
                .logout()
                .addLogoutHandler(new SPLogoutHandler())
                .logoutSuccessHandler(new SPmoduleLogoutSuccessHandler())
                .logoutSuccessUrl("/sp-logout").permitAll()
                .deleteCookies(sessionName)
                .and()
                .exceptionHandling().accessDeniedHandler(new SPAccessDeniedHanlder())
                ;
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new RoleSAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(new DefaultSAMLUserDetailsService());
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        samlAuthenticationProvider.setExcludeCredential(true);
        return samlAuthenticationProvider;
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        //otherwise the two localhost instances override each other session
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            sessionCookieConfig.setName(sessionName);
            sessionCookieConfig.setSecure(this.secureCookie);
            sessionCookieConfig.setHttpOnly(true);
        };
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);

        SAMLEntryPoint samlEntryPoint = new ConfigurableSAMLEntryPoint();
        samlEntryPoint.setFilterProcessesUrl("login");
        samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        return samlEntryPoint;
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(chain("/login/**", samlEntryPoint()));
        chains.add(chain("/metadata/**", metadataDisplayFilter()));
        chains.add(chain(assertionConsumerServiceURLPath + "/**", samlWebSSOProcessingFilter()));
        return new FilterChainProxy(chains);
    }

    private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
        return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setFilterProcessesUrl("saml/SSO");
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/launcher.html");
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }

    @Bean
    public MetadataProvider identityProvider() throws MetadataProviderException {
        MetadataProvider metadataProvider;
        boolean checkTrust = false;
        if (identityProviderMetadataUrl.startsWith("classpath")) {
            metadataProvider = new ResourceMetadataProvider(defaultResourceLoader.getResource(identityProviderMetadataUrl));
            ((ResourceMetadataProvider) metadataProvider).setParserPool(parserPool());
            checkTrust = true;
        } else {
            metadataProvider = new HTTPMetadataProvider(new Timer(true), new HttpClient(), identityProviderMetadataUrl);
            ((HTTPMetadataProvider) metadataProvider).setParserPool(parserPool());
        }
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(checkTrust);
        extendedMetadataDelegate.setMetadataRequireSignature(true);
        return extendedMetadataDelegate;
    }
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter()
            throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public MetadataGenerator metadataGenerator()
            throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(spEntityId);
        metadataGenerator.setEntityBaseURL(spBaseUrl);
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(identityProvider());
        return new CachingMetadataManager(providers);
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        DefaultMetadataDisplayFilter displayFilter = new DefaultMetadataDisplayFilter();
        displayFilter.setFilterProcessesUrl("metadata");
        return displayFilter;
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(true);
        return extendedMetadata;
    }

    @Bean
    public JKSKeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreLocator.createKeyStore(spPassphrase);
        KeyStoreLocator.addPrivateKey(keyStore, spEntityId, spPrivateKey, spCertificate, spPassphrase);
        return new JKSKeyManager(keyStore, Collections.singletonMap(spEntityId, spPassphrase), spEntityId);
    }

    @Bean
    public ParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public SAMLContextProvider contextProvider() throws URISyntaxException {
        return new ProxiedSAMLContextProviderLB(new URI(spBaseUrl), contextPath);
    }

    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    public static class ConfigurableSAMLEntryPoint extends SAMLEntryPoint {
        @Override
        protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException {
            WebSSOProfileOptions profileOptions = super.getProfileOptions(context, exception);
            InTransport inboundMessageTransport = context.getInboundMessageTransport();
            if (inboundMessageTransport instanceof HttpServletRequestAdapter) {
                HttpServletRequestAdapter messageTransport = (HttpServletRequestAdapter) inboundMessageTransport;
                String forceAuthn = messageTransport.getParameterValue("force-authn");
                if ("true".equals(forceAuthn)) {
                    profileOptions.setForceAuthN(true);
                }
            }
            ServletRequestAttributes servlet = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if(servlet != null){
                log.info("Before Session ID ===> {}", servlet.getSessionId());
            }
            return profileOptions;
        }
    }
}
