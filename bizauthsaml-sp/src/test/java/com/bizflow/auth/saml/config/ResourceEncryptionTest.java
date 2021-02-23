package com.bizflow.auth.saml.config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.junit.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
public class ResourceEncryptionTest {
    @Test
    public void exampleTest() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setProvider(new BouncyCastleProvider());
        encryptor.setPoolSize(2);
        encryptor.setPassword("7e646894667ee1dcc7b407bf91b8a3b8");
        encryptor.setAlgorithm("PBEWithSHA256And128BitAES-CBC-BC");

        String plainText = "saml-secret";
        String encryptedText = encryptor.encrypt(plainText);
        String decryptedText = encryptor.decrypt(encryptedText);
        System.out.println("ENC(" + encryptedText + ") Dec:" + decryptedText);
        assertEquals(plainText, encryptor.decrypt(encryptedText));
    }
}
