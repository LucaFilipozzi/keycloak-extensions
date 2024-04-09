// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.policy;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

@JBossLog
@AutoService(PasswordPolicyProviderFactory.class)
public class DisableUsersPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
  public static final String PROVIDER_ID = "disable-users-password-policy";

  @Override
  public PasswordPolicyProvider create(KeycloakSession session) {
    return new DisableUsersPasswordPolicyProvider();
  }

  @Override
  public void init(Config.Scope config) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayName() {
    return "Disable Users";
  }

  @Override
  public String getConfigType() {
    return PasswordPolicyProvider.INT_CONFIG_TYPE;
  }

  @Override
  public String getDefaultConfigValue() {
    return "60";
  }

  @Override
  public boolean isMultiplSupported() {
    return false;
  }
}
