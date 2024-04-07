// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.policy;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

@AutoService(PasswordPolicyProviderFactory.class)
public class CustomPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
  public static final String PROVIDER_ID = "custom-password-policy";

  @Override
  public String getDisplayName() {
    return null; // TODO
  }

  @Override
  public String getConfigType() {
    return null; // TODO
  }

  @Override
  public String getDefaultConfigValue() {
    return null; // TODO
  }

  @Override
  public boolean isMultiplSupported() {
    return false;
  }

  @Override
  public PasswordPolicyProvider create(KeycloakSession session) {
    return new CustomPasswordPolicyProvider(session);
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
}
