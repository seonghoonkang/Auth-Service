package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.api.IdpConfiguration;
import com.bizflow.auth.saml.SAMLBuilder;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.bizflow.auth.saml.SAMLBuilder.buildSAMLObject;

@Service("MetadataService")
public class MetadataServiceImpl implements MetadataService {
    @Autowired
    private IdpConfiguration idpConfiguration;
    @Autowired
    private KeyManager keyManager;
    @Autowired
    private Environment environment;

    @Value("${idp.base_url}")
    String baseUrl;
    @Value("${idp.context_path}")
    String contextPath;
    @Value("${management.api.sso_uri}")
    String ssoUri;
    @Value("${management.api.slo_uri}")
    String sloUri;

    @Override
    public String createMetadata() throws MarshallingException, SecurityException, SignatureException {
        //XML root
        EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID(idpConfiguration.getEntityId());
        entityDescriptor.setID(SAMLBuilder.randomSAMLId());
        entityDescriptor.setValidUntil(new DateTime().plusMillis(86400000));//expired metadata xml at 1 day

        Organization org = buildSAMLObject(Organization.class, Organization.DEFAULT_ELEMENT_NAME);

        OrganizationName oName = buildSAMLObject(OrganizationName.class, OrganizationName.DEFAULT_ELEMENT_NAME);
        oName.setName(new LocalizedString("Some Non-profit Organization of New York", "en"));
        org.getOrganizationNames().add(oName);

        OrganizationDisplayName oDisplayName = buildSAMLObject(OrganizationDisplayName.class, OrganizationDisplayName.DEFAULT_ELEMENT_NAME);
        oDisplayName.setName(new LocalizedString("Some Non-profit Organization", "en"));
        org.getDisplayNames().add(oDisplayName);

        OrganizationURL oUrl = buildSAMLObject(OrganizationURL.class, OrganizationURL.DEFAULT_ELEMENT_NAME);
        oUrl.setURL(new LocalizedString((new StringBuffer()).append(baseUrl).toString(), "en"));
        org.getURLs().add(oUrl);

        ContactPerson person = buildSAMLObject(ContactPerson.class, ContactPerson.DEFAULT_ELEMENT_NAME);
        SurName sName = buildSAMLObject(SurName.class, SurName.DEFAULT_ELEMENT_NAME);
        sName.setName("SAML Technical Support");
        person.setSurName(sName);
        EmailAddress mail = buildSAMLObject(EmailAddress.class, EmailAddress.DEFAULT_ELEMENT_NAME);
        mail.setAddress("skang@bizflow.com");
        person.getEmailAddresses().add(mail);

        entityDescriptor.setOrganization(org);
        entityDescriptor.getContactPersons().add(person);

        Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);
        //configured digital signing.
        Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(idpConfiguration.getEntityId())));
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        //add ds:Signature to md:EntityDescriptor
        entityDescriptor.setSignature(signature);

        Configuration.getMarshallerFactory().getMarshaller(entityDescriptor).marshall(entityDescriptor);
        Signer.signObject(signature);

        IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        idpssoDescriptor.getNameIDFormats().add(makeNamedIDFormat());
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        idpssoDescriptor.getSingleSignOnServices().addAll(SSOServiceFactory.INSTANCE.getMultiSSOService(
                environment.getProperty("management.acceptable_bind.sso").split(","),
                (new StringBuffer()).append(baseUrl).append(contextPath).append(ssoUri).toString()));
        idpssoDescriptor.getSingleLogoutServices().addAll(SLOServiceFactory.INSTANCE.getMultiSLOService(
                environment.getProperty("management.acceptable_bind.slo").split(","),
                (new StringBuffer()).append(baseUrl).append(contextPath).append(sloUri).toString()
        ));
//        idpssoDescriptor.getSingleLogoutServices().add(SLOServiceFactory.INSTANCE.createService("get",
//                (new StringBuffer()).append(baseUrl).append(contextPath).append(sloUri).toString()));

        //add md:KeyDescriptor to md:IDPSSODescriptor
        idpssoDescriptor.getKeyDescriptors().addAll(makeEncKeyDescriptor(credential));

        //add md:IDPSSODescriptor to md:EntityDescriptor
        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);
        //add md:EntityDescriptor
        return writeEntityDescriptor(entityDescriptor);
    }

    private NameIDFormat makeNamedIDFormat() {
        NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        return nameIDFormat;
    }

    private List<KeyDescriptor> makeEncKeyDescriptor(Credential credential) throws SecurityException {
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        ArrayList<KeyDescriptor> keyList = new ArrayList<>();
        for (UsageType type :
                Arrays.asList(UsageType.SIGNING, UsageType.ENCRYPTION)) {
            KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
            encKeyDescriptor.setUse(type);
            encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
            keyList.add(encKeyDescriptor);
        }
        return keyList;
    }


    private String writeEntityDescriptor(EntityDescriptor entityDescriptor) throws MarshallingException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(entityDescriptor);
        Element element = marshaller.marshall(entityDescriptor);
        return XMLHelper.nodeToString(element);
    }
}
