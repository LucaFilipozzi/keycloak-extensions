// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.policy;

import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

@JBossLog
@RequiredArgsConstructor
public class CustomPasswordPolicyProvider implements PasswordPolicyProvider {
  private final KeycloakSession session;

  @Override
  public PolicyError validate(RealmModel realm, UserModel user, String password) {
    UserModel authenticatedUser =
        session.getContext().getAuthenticationSession().getAuthenticatedUser();
    LOG.infof(
        "realm=%s user=%s authenticatedUser=%s",
        realm.getName(), user.getUsername(), authenticatedUser.getUsername());
    return null; // equivalent to 'no error'
  }

  @Override
  public PolicyError validate(String user, String password) {
    return null; // equivalent to 'no error'
  }

  @Override
  public Object parseConfig(String value) {
    return null; // TODO
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
