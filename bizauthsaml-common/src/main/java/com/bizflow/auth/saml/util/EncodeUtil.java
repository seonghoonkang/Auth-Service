package com.bizflow.auth.saml.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;

/**
 * Encode Utility
 *
 * @author JB.Kang
 * @version 2.3
 * @since 2.2
 */
public class EncodeUtil {
    static BitSet noNeedEncoding = null;

    static {
        noNeedEncoding = new BitSet(256);

        for (int i = 97; i <= 122; i++) noNeedEncoding.set(i);
        for (int i = 65; i <= 90; i++) noNeedEncoding.set(i);
        for (int i = 48; i <= 57; i++) noNeedEncoding.set(i);

        noNeedEncoding.set(45);
        noNeedEncoding.set(95);
        noNeedEncoding.set(46);
        noNeedEncoding.set(42);
    }

    /**
     * Converts a string to MD5 byte array
     *
     * @param content a string content
     * @return MD5 byte array
     */
    public static byte[] toMD5Bytes(String content) {
        try {
            return MessageDigest.getInstance("MD5").digest(content.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts a byte array to a hex string
     *
     * @param bytes byte array
     * @return a hex string
     */
    public static String toHexString(byte[] bytes) {
        StringBuffer buffer = new StringBuffer(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) buffer.append('0');
            buffer.append(hex);
            ;
        }
        return buffer.toString();
    }

    /**
     * Converts a string to MD5 string
     *
     * @param content a string content
     * @return a md5 hex string
     */
    public static String toMD5String(String content) {
        return toHexString(toMD5Bytes(content));
    }

    /**
     * Converts a hex string to byte array
     *
     * @param hexString a hex string
     * @return byte array
     * @since 2.3
     */
    public static byte[] hexStringToByteArray(String hexString) {
        int arrLength = hexString.length() >> 1;
        byte[] buf = new byte[arrLength];
        for (int ii = 0; ii < arrLength; ii++) {
            int index = ii << 1;
            String l_digit = hexString.substring(index, index + 2);
            buf[ii] = ((byte) Integer.parseInt(l_digit, 16));
        }
        return buf;
    }

    /**
     * Decode hex string to string
     *
     * @param hexString a hex string
     * @return a decoded string
     */
    public static String decodeHex(String hexString) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hexString.length(); i++) {
            char c = hexString.charAt(i);
            switch (c) {
                case 37: // '%'
                    if (hexString.charAt(i + 1) >= '0' && hexString.charAt(i + 1) <= '9' && hexString.charAt(i + 2) >= '0' && hexString.charAt(i + 2) <= '9') {
                        try {
                            sb.append((char) Integer.parseInt(hexString.substring(i + 1, i + 3), 16));
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException();
                        }
                        i += 2;
                        break;
                    }
                default:
                    sb.append(c);
                    break;
            }
        }

        String result = sb.toString();
        try {
            result = new String(result.getBytes("8859_1"));
        } catch (UnsupportedEncodingException e) {
        }
        return result;
    }

    /**
     * Encode string to hex string
     *
     * @param string source string
     * @return encoded hex string
     */
    public static String encode2Hex(String string) {
        int maxBytesPerChar = 10;
        StringBuilder out = new StringBuilder(string.length());
        ByteArrayOutputStream buf = new ByteArrayOutputStream(maxBytesPerChar);
        OutputStreamWriter writer = new OutputStreamWriter(buf);
        for (int i = 0; i < string.length(); i++) {
            int c = string.charAt(i);
            if (noNeedEncoding.get(c)) {
                out.append((char) c);
                continue;
            }
            try {
                writer.write(c);
                writer.flush();
            } catch (IOException e) {
                buf.reset();
                continue;
            }
            byte ba[] = buf.toByteArray();
            for (int j = 0; j < ba.length; j++) {
                out.append('x');
                char ch = Character.forDigit(ba[j] >> 4 & 0xf, 16);
                if (Character.isLetter(ch)) ch -= ' ';
                out.append(ch);
                ch = Character.forDigit(ba[j] & 0xf, 16);
                if (Character.isLetter(ch)) ch -= ' ';
                out.append(ch);
            }

            buf.reset();
        }

        return out.toString();
    }

}
