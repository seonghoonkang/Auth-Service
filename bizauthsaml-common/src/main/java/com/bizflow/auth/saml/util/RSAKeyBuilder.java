package com.bizflow.auth.saml.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Date;

import static java.security.KeyPairGenerator.getInstance;

public final class RSAKeyBuilder {
    private final X500Name certIssuer;
    private final X500Name certSubject;
    private final BigInteger certSerial;
    private final Date certNotBefore;
    private final Date certNotAfter;
    private final String certSignAlgorithm;
    private final int keySize;
    private final String keyGenAlgorithm;

    private RSAKeyBuilder(Builder builder) {
        this.certIssuer = builder.certIssuer;
        this.certSubject = builder.certSubject;
        this.certSerial = builder.certSerial == null ? new BigInteger(64, new SecureRandom()) : builder.certSerial;
        this.certNotBefore = builder.certNotBefore == null ?
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30) :
                builder.certNotBefore;
        this.certNotAfter = builder.certNotAfter == null ?
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)) :
                builder.certNotBefore;
        this.certSignAlgorithm = (builder.certSignAlgorithm == null) ? "SHA1withRSA" : builder.certSignAlgorithm;
        this.keySize = builder.keySize == 0 ? 2048 : builder.keySize;
        this.keyGenAlgorithm = builder.keyGenAlgorithm == null ? "RSA" : builder.keyGenAlgorithm;
    }

    public static final class Builder {
        private final X500Name certIssuer;
        private final X500Name certSubject;
        private BigInteger certSerial;
        private Date certNotBefore;
        private Date certNotAfter;
        private String certSignAlgorithm;
        private int keySize;
        private String keyGenAlgorithm;

        public Builder(X500NameBuilder issuer, X500NameBuilder subject) {
            this.certIssuer = issuer.build();
            this.certSubject = subject.build();
        }

        public Builder keySize(int val) {
            this.keySize = val;
            return this;
        }

        public Builder keyGenAlgorithm(String algorithm) {
            this.keyGenAlgorithm = algorithm;
            return this;
        }

        public Builder certSerial(BigInteger serial) {
            this.certSerial = serial;
            return this;
        }

        public Builder certNotBefore(Date notBefore) {
            this.certNotBefore = notBefore;
            return this;
        }

        public Builder certNotAfter(Date notAfter) {
            this.certNotAfter = notAfter;
            return this;
        }

        public Builder certSignAlgorithm(String algorithm) {
            this.certSignAlgorithm = algorithm;
            return this;
        }

        public RSAKeyPEMFamily build() throws NoSuchAlgorithmException, OperatorCreationException {
            return new RSAKeyPEMFamily(new RSAKeyBuilder(this));
        }
    }

    public static final class RSAKeyPEMFamily {
        RSAKeyBuilder builder;
        KeyPair keyPair;
        X509CertificateHolder x509Holder;

        public RSAKeyPEMFamily(RSAKeyBuilder builder) throws NoSuchAlgorithmException, OperatorCreationException {
            this.builder = builder;
            makeRSAKeyPair();
        }

        /*
        CN = Common Name
        O  = Organization (Company)
        OU = Organizational Unit
        DC = Domain Component (EX: DC=saml, DC=bizflow, DC=com)
        L  = Local
        C  = Country
        new X500Name("CN=admin, OU=BizAuth Team, O=Bizflow KLO, L=Seoul, C=KR"),
        new X500Name("CN=customer, OU=Test Team, O=Company, L=Virgina, C=US")
        */
        // Raw(unencrypted) Private-Key format :: PKCS#8 format "-----BEGIN PRIVATE KEY-----"
        public String getPrivateKeyPem() throws IOException {
            StringWriter stringWriter = new StringWriter();
            try (JcaPEMWriter pw = new JcaPEMWriter(stringWriter)) {
                JcaPKCS8Generator genPkcs8 = new JcaPKCS8Generator(this.keyPair.getPrivate(), null);
                PemObject pemObject = genPkcs8.generate();
                pw.writeObject(pemObject);
            }
            return stringWriter.toString();
        }

        public String getCertificationPem() throws IOException, CertificateException {
            StringWriter writer = new StringWriter();
            try(JcaPEMWriter pw = new JcaPEMWriter(writer)){
                pw.writeObject(new JcaX509CertificateConverter().getCertificate(x509Holder));
            }
            return writer.toString();
        }
//-- TODO Pem 형식 출력시 선택한 PKCS 스펙에 따라 출력하도록 코드 수정 필요
        public String getPrivateKeyHeadlessPem() throws IOException {
            return trimLine(getPrivateKeyPem());
        }

        public String getCertificationHeadlessPem() throws IOException, CertificateException {
            return trimLine(getCertificationPem());
        }

        private void makeCertification()
                throws SecurityException, OperatorCreationException {
            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(this.keyPair.getPublic().getEncoded());

            X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                    builder.certIssuer,
                    builder.certSerial,
                    builder.certNotBefore,
                    builder.certNotAfter,
                    builder.certSubject,
                    subPubKeyInfo);
            ContentSigner sigGen = new JcaContentSignerBuilder(builder.certSignAlgorithm).build(this.keyPair.getPrivate());
            this.x509Holder = v3CertGen.build(sigGen);
        }

        private void makeRSAKeyPair() throws NoSuchAlgorithmException, OperatorCreationException {
            SecureRandom random = SecureRandom.getInstanceStrong();
            KeyPairGenerator gen = getInstance(builder.keyGenAlgorithm);
            gen.initialize(builder.keySize, random);
            this.keyPair = gen.generateKeyPair();
            makeCertification();
        }
// Raw(unencrypted) Private-Key format :: PKCS#1 format "-----BEGIN RSA PRIVATE KEY-----"
//        private String transformToPem(Object orgBin, boolean headless) throws IOException {
//            StringWriter writer = new StringWriter();
//            JcaPEMWriter jcaPemWriter = new JcaPEMWriter(writer);
//            jcaPemWriter.writeObject(orgBin);
//            jcaPemWriter.flush();
//            jcaPemWriter.close();
//            if(headless){
//                return trimLine(writer.toString());
//            }
//            return writer.toString();
//        }

        private String trimLine(String pemString) throws IOException {
            StringReader stringReader = new StringReader(pemString);
            BufferedReader reader = new BufferedReader(stringReader);
            String temp;
            StringBuilder lines = new StringBuilder();
            while ((temp = reader.readLine()) != null) {
                if (temp.startsWith("-----")) continue;
                lines.append(temp).append(System.lineSeparator());
            }
            return lines.toString();
        }
    }

    public static void main(String[] args) {
        X500NameBuilder issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, "관리")
                .addRDN(BCStyle.OU, "비즈플로")
                .addRDN(BCStyle.O, "한국지")
                .addRDN(BCStyle.L, "서울")
                .addRDN(BCStyle.C, "KR")
                .addRDN(BCStyle.E, "kangpual@gmail.com")
                .addRDN(BCStyle.GIVENNAME, "담당자")
                ;
        X500NameBuilder subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, "Consumer")
                .addRDN(BCStyle.OU, "Test Team")
                .addRDN(BCStyle.O, "BCompany")
                .addRDN(BCStyle.L, "Virgina")
                .addRDN(BCStyle.C, "US");

        try {
            RSAKeyPEMFamily pemFamily = new Builder(issuer, subject).build();
            System.out.println(pemFamily.getCertificationPem());
            System.out.println(pemFamily.getPrivateKeyPem());
//            System.out.println(pemFamily.getPublicKeyPem());
        } catch (NoSuchAlgorithmException | IOException | OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }
    }
}
