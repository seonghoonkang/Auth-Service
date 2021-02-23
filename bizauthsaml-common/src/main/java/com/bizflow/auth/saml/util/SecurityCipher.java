package com.bizflow.auth.saml.util;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * SecurityCipher
 * <p>
 * local_policy.jar and US_export_policy.jar in jre\lib\security must be updated with the unlimited JCE Policy to use 256 bit AES
 *
 * @author JB.Kang
 * @version 2.2
 */
public class SecurityCipher {
    private static SecurityCipher instance = new SecurityCipher();
    private String key128 = "qWerTyUiJhGfcDvb"; // 128 bit key
    private String key256 = "VbjHgFdSWerTyUiOiPolKjNbGhJgfYhq"; // 256 bit key
    private String initVector = "bVcDrTyQpaSaCrTy"; // 16 bytes IV
    private String cipherCharset = "UTF-8"; // default cipher character set
    private int keyBit = 128;

    private int bcryptRound = 10; // default=10, available 4 ~ 16, if set a value over 12 then it have performance issues

    /**
     * Gets the instance of a default security cipher
     *
     * @return a default security cipher instance
     * @since 2.1
     */
    public static SecurityCipher getInstance() {
        return instance;
    }

    public String getKey128() {
        return key128;
    }

    /**
     * Sets 128 bit key
     *
     * @param key128 a 128 bit key
     */
    public void setKey128(String key128) {
        this.key128 = key128;
    }

    public String getKey256() {
        return key256;
    }

    /**
     * Sets 256 bit key
     *
     * @param key256 a 256 bit key
     * @since 2.5
     */
    public void setKey256(String key256) {
        this.key256 = key256;
    }

    public String getInitVector() {
        return initVector;
    }

    /**
     * Sets initial vector
     *
     * @param initVector an initial vector
     */
    public void setInitVector(String initVector) {
        this.initVector = initVector;
    }

    /**
     * Sets the cipher character set
     *
     * @param cipherCharset a character set
     */
    public void setCipherCharset(String cipherCharset) {
        this.cipherCharset = cipherCharset;
    }

    public int getKeyBit() {
        return keyBit;
    }

    public void setKeyBit(int keyBit) {
        this.keyBit = keyBit;
    }

    /**
     * Sets log round of Bcrypt
     *
     * @param bcryptRound a log round for encrypt
     */
    public void setBcryptRound(int bcryptRound) {
        this.bcryptRound = bcryptRound;
    }

    public int getBcryptRound() { return bcryptRound; }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @return encrypted value
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @since 3.0
     */
    public byte[] encipher(byte[] securityKey, byte[] ivParam, byte[] value) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(ivParam);
        SecretKeySpec secretKeySpec = new SecretKeySpec(securityKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        return cipher.doFinal(value);
    }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @param charset     character set
     * @return encrypted value
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encipher(byte[] securityKey, byte[] ivParam, String value, String charset) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encipher(securityKey, ivParam, value.getBytes(charset));
    }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @return encrypted value
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encipher(byte[] securityKey, byte[] ivParam, String value) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encipher(securityKey, ivParam, value, cipherCharset);
    }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @return encrypted value
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encipher(String securityKey, String ivParam, String value) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encipher(securityKey.getBytes(StandardCharsets.UTF_8), ivParam.getBytes(StandardCharsets.UTF_8), value);
    }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       source byte array
     * @return encrypted value
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encipher(String securityKey, String ivParam, byte[] value) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encipher(securityKey.getBytes("UTF-8"), ivParam.getBytes("UTF-8"), value);
    }

    /**
     * Enciphers a value and encodes it as a base64 string
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String encipherBase64(String securityKey, String ivParam, String value) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return Base64.encodeBase64String(encipher(securityKey, ivParam, value));
    }

    /**
     * Enciphers a value and encodes it as a base64 string
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source byte array
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @since 3.0
     */
    public String encipherBase64(String securityKey, String ivParam, byte[] value) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return Base64.encodeBase64String(encipher(securityKey, ivParam, value));
    }

    /**
     * Enciphers a value
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param value       a source string
     * @return encrypted value
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String encipherBase64(byte[] securityKey, byte[] ivParam, String value) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return Base64.encodeBase64String(encipher(securityKey, ivParam, value));
    }

    /**
     * Enciphers a value and encodes it as a base64 string
     *
     * @param value a source string
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String encipher128Base64(String value) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return Base64.encodeBase64String(encipher(key128, initVector, value));
    }

    /**
     * Enciphers a value by AES 256 bit and encodes it as a base64 string
     *
     * @param value a source string
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @since 2.5
     */
    public String encipher256Base64(String value) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return Base64.encodeBase64String(encipher(key256, initVector, value));
    }

    /**
     * Enciphers a value and encodes it as a base64 string
     *
     * @param value  a source string
     * @param keyBit key bit 128 or 256
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String encipherBase64(String value, int keyBit) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (256 == keyBit) return encipher256Base64(value);
        else return encipher128Base64(value);
    }

    /**
     * Enciphers a value and encodes it as a base64 string
     *
     * @param value a source string
     * @return a base64 string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String encipherBase64(String value) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return encipherBase64(value, keyBit);
    }

    /**
     * Deciphers an encrypted string
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param encrypted   an encrypted string
     * @return an original string
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decipher(byte[] securityKey, byte[] ivParam, byte[] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(ivParam);
        SecretKeySpec secretKeySpec = new SecretKeySpec(securityKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

        return cipher.doFinal(encrypted);
    }

    /**
     * Deciphers an encrypted string
     *
     * @param securityKey a security key
     * @param ivParam     initial IV parameter
     * @param encrypted   an encrypted string
     * @return an original string
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decipher(String securityKey, String ivParam, byte[] encrypted) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decipher(securityKey.getBytes(StandardCharsets.UTF_8), ivParam.getBytes(StandardCharsets.UTF_8), encrypted);
    }

    /**
     * Deciphers an encrypted string
     *
     * @param securityKey           a security key
     * @param ivParam               initial IV parameter
     * @param base64EncryptedString an encrypted string
     * @return an original string
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String decipherBase64(byte[] securityKey, byte[] ivParam, String base64EncryptedString) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] original = decipher(securityKey, ivParam, Base64.decodeBase64(base64EncryptedString));
        return new String(original, cipherCharset);
    }

    /**
     * Deciphers an base64 encrypted string
     *
     * @param securityKey           a security key
     * @param ivParam               initial IV parameter
     * @param base64EncryptedString an encrypted string
     * @return an original string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String decipherBase64(String securityKey, String ivParam, String base64EncryptedString) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        byte[] original = decipher(securityKey, ivParam, Base64.decodeBase64(base64EncryptedString));
        return new String(original, cipherCharset);
    }

    /**
     * Deciphers an base64 encrypted string
     *
     * @param base64EncryptedString an encrypted string
     * @return an original string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String decipher128Base64(String base64EncryptedString) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return decipherBase64(key128, initVector, base64EncryptedString);
    }

    /**
     * Deciphers an base64 256 bit encrypted string
     *
     * @param base64EncryptedString an encrypted string
     * @return an original string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @since 2.5
     */
    public String decipher256Base64(String base64EncryptedString) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return decipherBase64(key256, initVector, base64EncryptedString);
    }

    /**
     * Deciphers an base64 encrypted string
     *
     * @param base64EncryptedString an encrypted string
     * @param keyBit                key bit 128 or 256
     * @return an original string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String decipherBase64(String base64EncryptedString, int keyBit) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (256 == keyBit) return decipher256Base64(base64EncryptedString);
        else return decipher128Base64(base64EncryptedString);
    }

    /**
     * Deciphers an base64 encrypted string
     *
     * @param base64EncryptedString an encrypted string
     * @return an original string
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public String decipherBase64(String base64EncryptedString) throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return decipherBase64(base64EncryptedString, keyBit);
    }

    /**
     * Generates a key
     *
     * @param keySize key size, 128 or 256
     * @return a key
     * @throws NoSuchAlgorithmException
     * @since 2.5
     */
    public byte[] generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * Generates an initial vector
     *
     * @return an initial vector
     * @since 2.3
     */
    public byte[] generateIV() {
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Generates a key as a hex string
     *
     * @return a hex string key
     * @throws NoSuchAlgorithmException
     * @since 2.3
     */
    public String generateHexStringKey() throws NoSuchAlgorithmException {
        return EncodeUtil.toHexString(generateKey(keyBit));
    }

    /**
     * Generates an initial vector as a hex string
     *
     * @return a hex string initial vector string
     * @since 2.3
     */
    public String generateHexStringIV() {
        return EncodeUtil.toHexString(generateIV());
    }


    /**
     * BCrypt encrypts a string
     *
     * @param value a source string
     * @return
     */
    public String encryptToBcrypt(String value) {
        return BCrypt.hashpw(value, BCrypt.gensalt(bcryptRound));
    }

    /**
     * Check equals plaintext with hashed string for Password
     *
     * @param plaintext a plaintext string
     * @param hashed a hashed string
     * @return
     */
    public boolean isMatchPassword(String plaintext, String hashed) {
        return BCrypt.checkpw(plaintext, hashed);
    }


    public static void main(String[] args) throws NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String value = null;
        if ("-e".equalsIgnoreCase(args[0])) {
            value = SecurityCipher.instance.encipherBase64(args[1]);
        } else if ("-d".equalsIgnoreCase(args[0])) {
            value = SecurityCipher.instance.decipherBase64(args[1]);
        }

        System.out.println(value);

    }
}
