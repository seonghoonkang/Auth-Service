package com.bizflow.auth.saml.provider;

import com.bizflow.auth.saml.api.IdpConfiguration;
import com.bizflow.auth.saml.InvalidAuthenticationException;
import com.bizflow.auth.saml.model.FederatedUserAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

import static com.bizflow.auth.saml.api.AuthenticationMethod.ALL;

public class IdPAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {

  private final IdpConfiguration idpConfiguration;
  public final static String PREFIX_GRANT_AUTHORITY = "ROLE_";
  public IdPAuthenticationProvider(IdpConfiguration idpConfiguration) {
    this.idpConfiguration = idpConfiguration;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (StringUtils.isEmpty(authentication.getPrincipal())) {
      throw new InvalidAuthenticationException("Principal may not be empty");
    }
    if (idpConfiguration.getAuthenticationMethod().equals(ALL)) {
      List<SimpleGrantedAuthority> roleList = new ArrayList<>();
      IdpConfiguration.GRANT_TYPES.stream().map(type -> new SimpleGrantedAuthority(type)).forEach( grant -> roleList.add(grant));
      return new FederatedUserAuthenticationToken(
        authentication.getPrincipal(),
        authentication.getCredentials(), roleList);
    } else {
      String principal = (String) authentication.getPrincipal();
      String credentials = (String) authentication.getCredentials();
      return idpConfiguration.getUsersListString(principal, credentials);
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
