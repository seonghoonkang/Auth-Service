package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.dao.ServiceProviderDAO;
import com.bizflow.auth.saml.model.FingerPrintSet;
import com.bizflow.auth.saml.model.RSAKeySet;
import com.bizflow.auth.saml.model.ServiceProviderVO;
import com.bizflow.auth.saml.model.SubjectInfo;
import com.bizflow.auth.saml.util.RSAKeyBuilder;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Service("SPManagerService")
public class SPManagerServiceImpl implements SPManagerService {
    private ServiceProviderDAO serviceProviderDAO;

    @Autowired public SPManagerServiceImpl(ServiceProviderDAO serviceProviderDAO) {
        this.serviceProviderDAO = serviceProviderDAO;
    }

    @Override
    public RSAKeySet generateRSAKeyForSP(SubjectInfo subjectInfo) {
        X500NameBuilder subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, subjectInfo.getEntityId())
                .addRDN(BCStyle.OU, subjectInfo.getUnit())
                .addRDN(BCStyle.O, subjectInfo.getOrganization())
                .addRDN(BCStyle.L, subjectInfo.getLocal())
                .addRDN(BCStyle.C, subjectInfo.getCountry());
        X500NameBuilder issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, "Administrator")
                .addRDN(BCStyle.OU, "BizAuth Team")
                .addRDN(BCStyle.O, "Bizflow KLO")
                .addRDN(BCStyle.L, "Seoul")
                .addRDN(BCStyle.C, "KR")
                .addRDN(BCStyle.EmailAddress, "Admin@bizflowsaml.com");
        RSAKeySet keySet = new RSAKeySet();
        try {
            RSAKeyBuilder.RSAKeyPEMFamily pemFamily = new RSAKeyBuilder.Builder(issuer, subject)
//                    .certSignAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256)
                    .build();
            keySet.setPrivateKeyPEM(pemFamily.getPrivateKeyPem());
            keySet.setCertificationPEM(pemFamily.getCertificationPem());
        } catch (NoSuchAlgorithmException | IOException | OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }
        return keySet;
    }

    @Override
    public FingerPrintSet getIdPCertificationFingerPrint() throws Exception {
//        final X509Certificate clientCertX509 = CertificateClientManagement.loadCertificate("secure/cert/test.crt");
        FingerPrintSet vo = new FingerPrintSet();

        SHA256Digest sha256 = new SHA256Digest();
        SHA1Digest sha1 = new SHA1Digest();

        vo.setSHA1FingerPrint(creatFingerPrint(this.getClass().getResourceAsStream("/secure/idp.crt"), sha1));
        vo.setSHA256FingerPrint(creatFingerPrint(this.getClass().getResourceAsStream("/secure/idp.crt"), sha256));

        return vo;
    }

    @Override
    public ServiceProviderVO getServiceProviderInfo(String acsUrl) {
        return serviceProviderDAO.selectServiceProviderWithId(acsUrl);
    }

    private String creatFingerPrint(InputStream is, GeneralDigest digest) throws CertificateException, UnsupportedEncodingException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);

        byte[] der = cert.getEncoded();

        digest.update(der, 0, der.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);

        byte[] sha1 = result;
        byte[] hexBytes = Hex.encode(sha1);
        String hex = new String(hexBytes, "ASCII").toUpperCase();

        StringBuffer fp = new StringBuffer();
        int i = 0;
        fp.append(hex.substring(i, i + 2));
        while ((i += 2) < hex.length())
        {
            fp.append(':');
            fp.append(hex.substring(i, i + 2));
        }
        return fp.toString();
    }
}
