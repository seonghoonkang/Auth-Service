package com.bizflow.auth.saml.config;

import com.bizflow.auth.saml.api.ExceptionAttributes;
import com.bizflow.auth.saml.api.ExceptionAttributesImpl;
import com.bizflow.auth.saml.api.IdpConfiguration;
import com.bizflow.auth.saml.filter.ForceAuthnFilter;
import com.bizflow.auth.saml.filter.SAMLAttributeAuthenticationFilter;
import com.bizflow.auth.saml.filter.VerificationSPFilter;
import com.bizflow.auth.saml.handler.LoginFailureHandler;
import com.bizflow.auth.saml.handler.SAMLMessageHandler;
import com.bizflow.auth.saml.provider.IdPAuthenticationProvider;
import com.bizflow.auth.saml.KeyStoreLocator;
import com.bizflow.auth.saml.UpgradedSAMLBootstrap;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring5.ISpringTemplateEngine;
import org.thymeleaf.spring5.SpringTemplateEngine;
import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring5.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ITemplateResolver;

import javax.servlet.SessionCookieConfig;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@PropertySource("classpath:application.properties")
@EnableWebSecurity
@EnableWebMvc
@ComponentScan(basePackages = {"com.bizflow.auth.saml"})
public class WebSecurityConfigurer implements WebMvcConfigurer {

    private final ApplicationContext applicationContext;

    @Value("${secure_cookie}")
    private boolean secureCookie;

    @Autowired public WebSecurityConfigurer(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Bean
    public ExceptionAttributes exceptionAttributes() {
        return new ExceptionAttributesImpl();
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(MapperFeature.DEFAULT_VIEW_INCLUSION, true);

        return mapper;
    }

//    @Override
//    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
//        converters.add(new ResourceHttpMessageConverter(true));
//    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry){
        registry.addResourceHandler("/res/**")
                .addResourceLocations("classpath:/public/").setCachePeriod(3600)
                .resourceChain(true)
                .addResolver(new PathResourceResolver());
    }
    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer.defaultContentType(MediaType.valueOf("application/json"), MediaType.valueOf("application/xml"));
    }
    /**
     * Thymeleaf 뷰 리졸버 설정
     */
    @Bean
    public ViewResolver viewResolver() {
        ThymeleafViewResolver resolver = new ThymeleafViewResolver();
        resolver.setTemplateEngine((ISpringTemplateEngine) templateEngine());
        resolver.setCharacterEncoding("UTF-8");
        return resolver;
    }

    @Bean
    public TemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setEnableSpringELCompiler(true);
        engine.setTemplateResolver(templateResolver());
        return engine;
    }

    private ITemplateResolver templateResolver() {

        SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
        resolver.setApplicationContext(applicationContext);
        resolver.setPrefix("classpath:/templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        return resolver;
    }

    @Bean
    @Autowired
    public SAMLMessageHandler samlMessageHandler(@Value("${idp.clock_skew}") int clockSkew,
                                                 @Value("${idp.expires}") int expires,
                                                 @Value("${idp.base_url}") String idpBaseUrl,
                                                 @Value("${idp.compare_endpoints}") boolean compareEndpoints,
                                                 @Value("${idp.context_path}") String contextPath,
                                                 IdpConfiguration idpConfiguration,
                                                 JKSKeyManager keyManager)
            throws XMLParserException, URISyntaxException {
//  Setup OpenSAML Basic config
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
//  Configure SAML Message connection
        securityPolicy.getPolicyRules().addAll(Collections.singletonList(new IssueInstantRule(clockSkew, expires)));

//  Configure HTTP Redirection and Post Binding
        HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder(parserPool);
        HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder(parserPool);
        if (!compareEndpoints) {
            URIComparator noopComparator = (uri1, uri2) -> true;
            httpPostDecoder.setURIComparator(noopComparator);
            httpRedirectDeflateDecoder.setURIComparator(noopComparator);
        }
//  SAML XML Parser Initialize
        parserPool.initialize();

        HTTPPostSimpleSignEncoder httpPostSimpleSignEncoder = new HTTPPostSimpleSignEncoder(VelocityFactory.getEngine(), "/templates/saml2-post-simplesign-binding.vm", true);

        return new SAMLMessageHandler(
                keyManager,
                Arrays.asList(httpRedirectDeflateDecoder, httpPostDecoder),
                httpPostSimpleSignEncoder,
                new StaticSecurityPolicyResolver(securityPolicy),
                idpConfiguration,
                idpBaseUrl,
                contextPath);
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new UpgradedSAMLBootstrap();
    }

    @Autowired
    @Bean
    public JKSKeyManager keyManager(@Value("${idp.entity_id}") String idpEntityId,
                                    @Value("${idp.private_key}") String idpPrivateKey,
                                    @Value("${idp.certificate}") String idpCertificate,
                                    @Value("${idp.passphrase}") String idpPassphrase) throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreLocator.createKeyStore(idpPassphrase);
        KeyStoreLocator.addPrivateKey(keyStore, idpEntityId, idpPrivateKey, idpCertificate, idpPassphrase);
        return new JKSKeyManager(keyStore, Collections.singletonMap(idpEntityId, idpPassphrase), idpEntityId);
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        //otherwise the two localhost instances override each other session
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            sessionCookieConfig.setName("JSessionId");
            sessionCookieConfig.setSecure(this.secureCookie);
            sessionCookieConfig.setHttpOnly(true);
        };
    }

    @Configuration
    public static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

        private final IdpConfiguration idpConfiguration;

        private final SAMLMessageHandler samlMessageHandler;

        @Autowired public ApplicationSecurity(IdpConfiguration idpConfiguration, SAMLMessageHandler samlMessageHandler) {
            this.idpConfiguration = idpConfiguration;
            this.samlMessageHandler = samlMessageHandler;
        }

        private SAMLAttributeAuthenticationFilter authenticationFilter() throws Exception {
            SAMLAttributeAuthenticationFilter filter = new SAMLAttributeAuthenticationFilter();
            filter.setAuthenticationManager(authenticationManagerBean());
//      filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
            filter.setAuthenticationFailureHandler(new LoginFailureHandler("/login?error=true"));
            return filter;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(new ForceAuthnFilter(samlMessageHandler), SAMLAttributeAuthenticationFilter.class)
                    .addFilterBefore(new VerificationSPFilter(getApplicationContext(), samlMessageHandler), ForceAuthnFilter.class)
                    .authorizeRequests()
                    .antMatchers("/", "/login", "/metadata", "/fingerprint", "/favicon.ico", "/api/**", "/res/**").permitAll()
                    .antMatchers("/admin/**").hasRole("ADM")
                    .anyRequest().hasRole("USR")
                    .and()
                    .formLogin()
                    .loginPage("/login").permitAll()
                    .and()
                    .logout()
                    .logoutUrl("/logout").permitAll()
                    .logoutSuccessUrl("/");
        }

        @Override
        public void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(new IdPAuthenticationProvider(idpConfiguration));
        }

        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }
    }

}
