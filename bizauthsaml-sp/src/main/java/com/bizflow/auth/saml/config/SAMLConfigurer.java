package com.bizflow.auth.saml.config;

import com.bizflow.auth.saml.UpgradedSAMLBootstrap;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IndexedEndpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.websso.*;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
public class SAMLConfigurer {
    private final Environment environment;

    @Autowired
    public SAMLConfigurer(Environment environment) {
        this.environment = environment;
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }

    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new UpgradedSAMLBootstrap();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Autowired
    @Bean
    public SAMLProcessor processor(VelocityEngine velocityEngine,
                                   ParserPool parserPool,
                                   SSOConfigurer ssoConfig,
                                   @Value("${sp.compare_endpoints}") boolean compareEndpoints) throws XMLParserException {
        ArtifactResolutionProfile artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
        StaticBasicParserPool pool = (StaticBasicParserPool) parserPool;
        if(!pool.isInitialized()){
            pool.initialize();
        }

        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding(pool));
        bindings.add(httpPostBinding(pool, velocityEngine, compareEndpoints));
        bindings.add(artifactBinding(pool, velocityEngine, artifactResolutionProfile));
        bindings.add(httpSOAP11Binding(pool));
        bindings.add(httpPAOS11Binding(pool));
        return new ConfigurableSAMLProcessor(bindings, ssoConfig);
    }

    @Bean
    @Autowired
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding(ParserPool parserPool) {
        return new HTTPRedirectDeflateBinding(parserPool);
    }
    @Bean
    @Autowired
    public HTTPPostBinding httpPostBinding(ParserPool parserPool, VelocityEngine velocityEngine, @Value("${sp.compare_endpoints}") boolean compareEndpoints) {
        HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
        HTTPPostDecoder decoder = new HTTPPostDecoder(parserPool);
        if (!compareEndpoints) {
            decoder.setURIComparator((uri1, uri2) -> true);
        }
        return new HTTPPostBinding(parserPool, decoder, encoder);
    }
    private HTTPArtifactBinding artifactBinding(ParserPool parserPool,
                                                VelocityEngine velocityEngine,
                                                ArtifactResolutionProfile artifactResolutionProfile) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile);
    }

    @Bean
    @Autowired
    public HTTPSOAP11Binding soapBinding(ParserPool parserPool) {
        return new HTTPSOAP11Binding(parserPool);
    }

    @Bean
    @Autowired
    public HTTPSOAP11Binding httpSOAP11Binding(ParserPool parserPool) {
        return new HTTPSOAP11Binding(parserPool);
    }

    @Bean
    @Autowired
    public HTTPPAOS11Binding httpPAOS11Binding(ParserPool parserPool) {
        return new HTTPPAOS11Binding(parserPool);
    }

    @Bean
    @Autowired
    public WebSSOProfile webSSOprofile(SAMLProcessor samlProcessor) {
        WebSSOProfileImpl webSSOProfile = new WebSSOProfileImpl();
        webSSOProfile.setProcessor(samlProcessor);
        return webSSOProfile;
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        WebSSOProfileConsumerImpl webSSOProfileConsumer = environment.acceptsProfiles(Profiles.of("test")) ?
                new WebSSOProfileConsumerImpl() {
                    @Override
                    @SuppressWarnings("unchecked")
                    protected void verifyAssertion(Assertion assertion, AuthnRequest request, SAMLMessageContext context) throws AuthenticationException {
                        //nope
                        context.setSubjectNameIdentifier(assertion.getSubject().getNameID());
                    }
                } : new WebSSOProfileConsumerImpl();
        webSSOProfileConsumer.setResponseSkew(15 * 60);
        return webSSOProfileConsumer;
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }

    public static class ConfigurableSAMLProcessor extends SAMLProcessorImpl{

        private final SSOConfigurer ssoConfigurer;

        public ConfigurableSAMLProcessor(Collection<SAMLBinding> bindings, SSOConfigurer ssoConfigurer) {
            super(bindings);
            this.ssoConfigurer = ssoConfigurer;
        }

        @Override
        public SAMLMessageContext sendMessage(SAMLMessageContext samlContext, boolean sign)
                throws SAMLException, MetadataProviderException, MessageEncodingException {


            Endpoint endpoint = samlContext.getPeerEntityEndpoint();

            SAMLBinding binding = getBinding(endpoint);

            samlContext.setLocalEntityId(ssoConfigurer.getEntityId());
            samlContext.getLocalEntityMetadata().setEntityID(ssoConfigurer.getEntityId());
            samlContext.getPeerEntityEndpoint().setLocation(ssoConfigurer.getIdpSSOServiceURL());

            SPSSODescriptor roleDescriptor = (SPSSODescriptor) samlContext.getLocalEntityMetadata().getRoleDescriptors().get(0);
            AssertionConsumerService assertionConsumerService =
                    roleDescriptor.getAssertionConsumerServices().stream()
                            .filter(IndexedEndpoint::isDefault)
                            .findAny()
                            .orElseThrow(() -> new RuntimeException("No default ACS"));
            assertionConsumerService.setBinding(ssoConfigurer.getProtocolBinding());
            assertionConsumerService.setLocation(ssoConfigurer.getAssertionConsumerServiceURL());

            return super.sendMessage(samlContext, ssoConfigurer.isNeedsSigning(), binding);

        }
    }
}
