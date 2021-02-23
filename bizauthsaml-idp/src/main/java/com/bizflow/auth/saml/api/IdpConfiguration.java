package com.bizflow.auth.saml.api;

import com.bizflow.auth.saml.InvalidAuthenticationException;
import com.bizflow.auth.saml.dao.UserDetailDAO;
import com.bizflow.auth.saml.model.FederatedUserAuthenticationToken;
import com.bizflow.auth.saml.model.UserDetailVO;
import com.bizflow.auth.saml.util.SecurityCipher;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

import java.util.*;

@Getter
@Setter
@Component
public class IdpConfiguration extends SharedConfiguration {

    private String defaultEntityId;
    private Map<String, List<String>> attributes = new TreeMap<>();
    private List<FederatedUserAuthenticationToken> users = new ArrayList<>();
    private String acsEndpoint;
    private AuthenticationMethod authenticationMethod;
    private AuthenticationMethod defaultAuthenticationMethod;
    private final String idpPrivateKey;
    private final String idpCertificate;
    private final static String PREFIX_GRANT_NAME = "ROLE_";
    public static List<String> GRANT_TYPES;
    private UserDetailDAO userDetailDAO;

    @Autowired
    public IdpConfiguration(JKSKeyManager keyManager,
                            UserDetailDAO userDetailDAO,
                            @Value("${idp.entity_id}") String defaultEntityId,
                            @Value("${idp.private_key}") String idpPrivateKey,
                            @Value("${idp.certificate}") String idpCertificate,
                            @Value("${idp.auth_method}") String authMethod,
                            @Value("${idp.passphrase}") String passphrase,
                            @Value("${idp.default_grant_type}") String grantType) {
        super(keyManager);
        this.userDetailDAO = userDetailDAO;
        this.defaultEntityId = defaultEntityId;
        this.idpPrivateKey = idpPrivateKey;
        this.idpCertificate = idpCertificate;
        this.defaultAuthenticationMethod = AuthenticationMethod.valueOf(authMethod);
        createGrantList(grantType);
        setKeystorePassword(passphrase);
        reset();
    }

    private void createGrantList(String grantType) {
        GRANT_TYPES = new ArrayList<>();
        for (String type: grantType.split(",")) {
            GRANT_TYPES.add(PREFIX_GRANT_NAME + type.trim().toUpperCase());
        }
    }

    @Override
    public void reset() {
        setEntityId(defaultEntityId);
        resetAttributes();
        resetKeyStore(defaultEntityId, idpPrivateKey, idpCertificate);
        resetUsers();
        setAcsEndpoint(null);
        setAuthenticationMethod(this.defaultAuthenticationMethod);
        setSignatureAlgorithm(getDefaultSignatureAlgorithm());
    }

    public Authentication getUsersListString(String principal, String credentials) {
        HashMap<String, String> param = new HashMap<>();
        param.put("loginId", principal);
        List<UserDetailVO> users = userDetailDAO.selectUserList(param);

        final boolean[] isReject = {true};
        ArrayList<SimpleGrantedAuthority> authority = new ArrayList<>();

        for (UserDetailVO user : users) {
            if (SecurityCipher.getInstance().isMatchPassword(credentials, user.getPassword())) {
                isReject[0] = false;
                if(GRANT_TYPES.contains(PREFIX_GRANT_NAME + user.getAuthCode())){
                    authority.add(new SimpleGrantedAuthority(IdpConfiguration.PREFIX_GRANT_NAME + user.getAuthCode()));
                }
            }
        }

        if (isReject[0]) {
            throw new InvalidAuthenticationException("User not found or bad credentials");
        }else if(!users.get(0).isActive()){
            throw new InvalidAuthenticationException("User not Active");
        }
        if(users.get(0).getAuthCode().equalsIgnoreCase("adm")){
            authority.add(new SimpleGrantedAuthority(PREFIX_GRANT_NAME + "USR"));
        }
        attributes.clear();
        putAttribute("urn:mace:dir:attribute-def:email", users.get(0).getEMail());
        putAttribute("urn:mace:dir:attribute-def:uname", users.get(0).getName());
        putAttribute("urn:mace:dir:attribute-def:uid", users.get(0).getUserId());
        putAttribute("urn:mace:dir:attribute-def:lid", users.get(0).getLoginId());
        putAttribute("urn:mace:dir:attribute-def:ou", users.get(0).getDeptName());
        putAttribute("urn:mace:dir:attribute-def:phone", users.get(0).getPhone());
        putAttribute("urn:mace:dir:attribute-def:dob", users.get(0).getDob());
        putAttribute("urn:mace:dir:attribute-def:title", users.get(0).getTitleName());
        putAttribute("urn:mace:dir:attribute-def:purl", "http://");
        return new FederatedUserAuthenticationToken(
                users.get(0).getLoginId(),
                users.get(0).getPassword(),
                authority);
    }

    private void resetUsers() {
        users.clear();
        users.addAll(Arrays.asList(
                new FederatedUserAuthenticationToken("admin", "secret", Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_USR"), new SimpleGrantedAuthority("ROLE_ADM"))
                ),
                new FederatedUserAuthenticationToken("user", "secret", Collections.singletonList(
                        new SimpleGrantedAuthority("ROLE_USR")
                ))
        ));
    }

    private void resetAttributes() {
        attributes.clear();
        putAttribute("urn:mace:terena.org:attribute-def:schacHomeOrganization", "bizflow.com");
        putAttribute("urn:mace:dir:attribute-def:email", "j.doe@bizlfow.com");
        putAttribute("urn:mace:dir:attribute-def:uid", "00000000");
        putAttribute("urn:mace:dir:attribute-def:uname", "John");
        putAttribute("urn:mace:dir:attribute-def:lid", "jdoe");
        putAttribute("urn:mace:dir:attribute-def:ou", "depart");
        putAttribute("urn:mace:dir:attribute-def:phone", "010-000-0000");
        putAttribute("urn:mace:dir:attribute-def:dob", "01/01/1900");
        putAttribute("urn:mace:dir:attribute-def:title", "Job Title");
        putAttribute("urn:mace:dir:attribute-def:purl", "https://img.theqoo.net/img/miDDe.jpg");
    }

    private void putAttribute(String key, String... values) {
        this.attributes.put(key, Arrays.asList(values));
    }

}
