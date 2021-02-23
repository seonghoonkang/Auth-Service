package com.bizflow.auth.saml.config;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableEncryptableProperties
public class ResourceEncryptionConfigurer {
    protected final Logger LOG = LoggerFactory.getLogger(getClass());

    @Bean("encryptorBean")
    public PooledPBEStringEncryptor stringEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setProvider(new BouncyCastleProvider());
        encryptor.setPoolSize(2);
        encryptor.setPassword("7e646894667ee1dcc7b407bf91b8a3b8");
        encryptor.setAlgorithm("PBEWithSHA256And128BitAES-CBC-BC");
        return encryptor;
    }
}
