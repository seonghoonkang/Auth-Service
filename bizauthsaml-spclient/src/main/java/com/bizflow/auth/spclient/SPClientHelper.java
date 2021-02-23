package com.bizflow.auth.spclient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.bizflow.auth.spclient.utils.CipherAssist;
import com.bizflow.auth.spclient.utils.OTPProvider;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * A SPClientHelper class is the Builder that help to decoding enc-token and to getting token claim.
 * For example:
 * <pre>
 * TokenAssistant assistant = new TokenAssistantBuilder(randomKey, secretKey, encAuthToken)
 *                 .setReferer(referer)
 *                 .setSPModuleBaseUrl(new URL(baseUrl))
 *                 .setTokenExpiryDuration(86400)
 *                 .build();
 * </pre>
 *
 * @author Paul, kang
 * @version 1.2.0 12/18/20
 * @see com.bizflow.auth.spclient.SPClientHelper.TokenAssistant
 * @see com.bizflow.auth.spclient.SPClientHelper.TokenAssistantBuilder
 */
public final class SPClientHelper {
    private final String instanceKey;
    private final String secretKey;
    private final String encAuthToken;
    private final long tokenExpiryDuration;
    private final String referer;
    private final URL endpoint;

    private SPClientHelper(TokenAssistantBuilder builder) {
        this.instanceKey = builder.tempKey;
        this.secretKey = builder.password;
        this.encAuthToken = builder.encAuthToken;
        this.referer = builder.referer;
        this.endpoint = builder.endpoint;
        this.tokenExpiryDuration = builder.tokenExpiryDuration;
    }

    /**
     * Token Assistant Builder.
     *
     * @author Paul, kang
     * @version 1.2.0 12/18/20
     */
    public static final class TokenAssistantBuilder {
        private final String tempKey;
        private final String password;
        private final String encAuthToken;

        private long tokenExpiryDuration;
        private String referer;
        private URL endpoint;

        /**
         * Token Assistant Builder Constructor
         *
         * @param randomKey   Authentication protocol flow 의 인증요청 Transaction ID.
         * @param secretKey   BizAuth-SP로 부터 발급받은 Client 비밀번호
         * @param token       BizAuthSAML-SP로 부터 전달받은 암호화된 토큰
         */
        public TokenAssistantBuilder(String randomKey, String secretKey, String token) {
            this.tempKey = randomKey;
            this.password = secretKey;
            this.encAuthToken = token;
        }

        /**
         * BizAuthSAML-SP의 시간동기화 API같은 OpenAPI를 사용하기 위해 BizAuthSAML-SP 주소를 저장한다.
         *
         * @param baseUrl BizAuth-SP이 이 위치한 Domain/subDomain 정보. 기본값 "http://authentication.bizflow.com/bizauthsaml-sp"
         * @return this
         */
        public TokenAssistantBuilder setSPModuleBaseUrl(URL baseUrl) {
            this.endpoint = baseUrl;
            return this;
        }

        /**
         * JWT 토큰에 기록된 발행인 주소(BizAuthSAML-SPbaseURL)와 referrer 정보를 비교하여 위조를 방지한다.
         *
         * @param referer request.getHeader("referer") 정보. 설정하지 않거나 'null'을 설정하면 사용하지 않는다.
         * @return this
         */
        public TokenAssistantBuilder setReferer(String referer) {
            this.referer = referer;
            return this;
        }

        /**
         * JWT 토큰의 발행일시를 기준으로 만료기간을 설정한다. BizAuthSAML-SP에 설정한 값과 동일하게 설정해야한다.
         *
         * @param tokenExpiryDuration 토큰 만료기간. 초 단위며 1day(86400) 기본값 이다.
         * @return this
         */
        public TokenAssistantBuilder setTokenExpiryDuration(int tokenExpiryDuration) {
            this.tokenExpiryDuration = tokenExpiryDuration;
            return this;
        }

        public TokenAssistant build() throws Exception {
            return new TokenAssistant(new SPClientHelper(this));
        }
    }

    /**
     * Token Assistant.
     *
     * @author Paul, kang
     * @version 1.2.0 12/18/20
     */
    public static final class TokenAssistant {
        private final SPClientHelper clientHelper;
        private final CipherAssist cipher;
        private final long tokenExpiryDuration;
        private final URL endpoint;
        private static DecodedJWT jwt;
        private static String aesSeed;
        private String referer;

        private final MessageDigest messageDigest;

        /**
         * JWT token 안에 기록된 jwt claim 정보 중 로그인한 사용자의 권한그룹 목록을 가져온다.
         *
         * @throws JWTVerificationException
         */
        public TokenAssistant(SPClientHelper clientHelper) throws Exception {
            this.clientHelper = clientHelper;
            this.cipher = CipherAssist.getInstance();
            this.messageDigest = MessageDigest.getInstance("MD5");
            this.referer = clientHelper.referer;
            this.tokenExpiryDuration = clientHelper.tokenExpiryDuration == 0 ? 86400 : clientHelper.tokenExpiryDuration;
            this.endpoint = clientHelper.endpoint == null ? new URL("https://authentication.bizflow.com/bizauthsaml-sp") : clientHelper.endpoint;
            aesSeed = createAesSeed();
            jwt = decodeJwtToken();
        }

        private String createAesSeed() {
            messageDigest.update(clientHelper.secretKey.getBytes(StandardCharsets.UTF_8));
            return CipherAssist.toHexString(messageDigest.digest());
        }

        private DecodedJWT decodeJwtToken() {
            if (referer != null && referer.trim().equals("")) {
                referer = null;
            }
            cipher.setKey256(aesSeed);
            cipher.setInitVector(clientHelper.instanceKey);
            try {
                jwt = JWT.require(Algorithm.HMAC256(clientHelper.secretKey))
                        .withIssuer(referer)
                        .acceptExpiresAt(tokenExpiryDuration).build()
                        .verify(cipher.decipher256Base64(clientHelper.encAuthToken));
            } catch (JWTVerificationException e) {
                throw new JWTVerificationException("Failed Authentication. invalid token. may be Expired jwt");
            } catch (Exception e) {
                throw new JWTVerificationException(e.getMessage());
            }
            return jwt;
        }

        /**
         * JWT token 안에 기록된 jwt claim 정보 중 로그인한 사용자의 권한그룹 목록을 가져온다.
         *
         * @return 권한그룹 목록.
         */
        public Map[] getUserAuthList() {
            return jwt.getClaim("userAuthList").asArray(Map.class);
        }

        /**
         * JWT token 안에 기록된 jwt claim 정보 중 로그인한 사용자의 사용자 그룹 목록을 가져온다.
         *
         * @return 사용자 그룹 목록.
         */
        public Map[] getUserGroupList() {
            return jwt.getClaim("userGroupList").asArray(Map.class);
        }

        /**
         * BPM 인증에 의존성을 가질 경우 BPM에서 발급한 인증토큰(SessionInfoXML)의 정보를 가져온다.
         *
         * @return BMP SessionInfoXML 속성 및 값.
         */
        public Map getBpmSessionInfo() {
            return jwt.getClaim("bpmSessionInfo").asMap();
        }

        /**
         * JWT token 안에 기록된 jwt claim 정보 중 로그인한 사용자의 기본정보를 가져온다.
         *
         * @return 사용자 정보
         */
        public Map getUserInfo() {
            return jwt.getClaim("userInfo").asMap();
        }

        /**
         * 시간동기화 OTP 를 발생시켜 TrustKey 를 생성한다.
         *
         * @return 사용자 정보
         * @throws Exception
         */
        public String getTrustKey() throws Exception {
            OTPProvider otp = OTPProvider.TIME_SYNC;
            otp.setOpenApiEndpoint(endpoint.toString());
            cipher.setInitVector(otp.generateOtp());
            cipher.setKey256(aesSeed);
            return cipher.encipher256Base64(clientHelper.secretKey);
        }

        /**
         * 암호화된 토큰 문자열을 해시코드로 변환한다.
         *
         * @return Encode token hashcode
         */
        public String getTokenHashCode() {
            StringBuilder stringBuilder = new StringBuilder();
            messageDigest.update(clientHelper.encAuthToken.getBytes());
            for (byte bytes : messageDigest.digest()) {
                stringBuilder.append(String.format("%02x", bytes & 0xff));
            }
            return stringBuilder.toString();
        }

    }

    /**
     * Authentication protocol flow 의 인증요청 Transaction ID를 생성한다.
     *
     * @return random key
     */
    public static String generateInstanceId() {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789"
                + "abcdefghijklmnopqrstuvxyz";

        StringBuilder sb = new StringBuilder(16);

        for (int i = 0; i < 16; i++) {
            int index
                    = (int) (AlphaNumericString.length()
                    * Math.random());
            sb.append(AlphaNumericString
                    .charAt(index));
        }
        return sb.toString();
    }

}
