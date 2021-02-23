package com.bizflow.auth.spclient.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CipherAssist {
    private static CipherAssist instance = new CipherAssist();
    private String key256 = "VbjHgFdSWerTyUiOiPolKjNbGhJgfYhq"; // 256 bit key
    private String initVector = "bVcDrTyQpaSaCrTy"; // 16 bytes IV
    private String cipherCharset = "UTF-8"; // default cipher character set

    public static CipherAssist getInstance() { return instance; }

    public void setKey256(String key256) { this.key256 = key256; }
    public void setInitVector(String initVector) {
        this.initVector = initVector;
    }
    public String getKey256() { return key256; }
    public String getInitVector() {
        return initVector;
    }

    public String encipher256Base64(String value) throws Exception {
        return Base64.getEncoder().encodeToString(encipher(key256, initVector, value));
    }

    public byte[] encipher(String securityKey, String ivParam, String value) throws Exception {
        return encipher(securityKey.getBytes(StandardCharsets.UTF_8), ivParam.getBytes(StandardCharsets.UTF_8), value);
    }

    public byte[] encipher(byte[] securityKey, byte[] ivParam, String value) throws Exception{
        return encipher(securityKey, ivParam, value.getBytes(cipherCharset));
    }

    private byte[] encipher(byte[] securityKey, byte[] ivParam, byte[] value) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(ivParam);
        SecretKeySpec secretKeySpec = new SecretKeySpec(securityKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        return cipher.doFinal(value);
    }

    public static String toHexString(byte[] bytes) {
        StringBuffer buffer = new StringBuffer(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) buffer.append('0');
            buffer.append(hex);
        }
        return buffer.toString();
    }

    public String decipher256Base64(String base64EncryptedString) throws Exception {
        return decipherBase64(key256, initVector, base64EncryptedString);
    }

    public String decipherBase64(String securityKey, String ivParam, String base64EncryptedString) throws Exception {
        byte[] original = decipher(securityKey, ivParam, Base64.getDecoder().decode(base64EncryptedString));
        return new String(original, cipherCharset);
    }

    public byte[] decipher(String securityKey, String ivParam, byte[] encrypted) throws Exception {
        return decipher(securityKey.getBytes(StandardCharsets.UTF_8), ivParam.getBytes(StandardCharsets.UTF_8), encrypted);
    }

    public byte[] decipher(byte[] securityKey, byte[] ivParam, byte[] encrypted) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(ivParam);
        SecretKeySpec secretKeySpec = new SecretKeySpec(securityKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

        return cipher.doFinal(encrypted);
    }
}
