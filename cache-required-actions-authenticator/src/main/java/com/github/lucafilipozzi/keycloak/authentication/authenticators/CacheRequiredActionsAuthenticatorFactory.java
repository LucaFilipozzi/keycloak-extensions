// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import static com.github.lucafilipozzi.keycloak.authentication.authenticators.CacheRequiredActionsAuthenticator.RESTORE_PROPERTY_ID;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;

import java.util.List;

import com.google.auto.service.AutoService;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

@AutoService(AuthenticatorFactory.class)
public class CacheRequiredActionsAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "cache-required-actions-authenticator";

  private static final Requirement[] REQUIREMENT_CHOICES = { REQUIRED, DISABLED };

  private static final CacheRequiredActionsAuthenticator SINGLETON = new CacheRequiredActionsAuthenticator();

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    CONFIG_PROPERTIES = ProviderConfigurationBuilder
        .create()
        .property()
        .name(RESTORE_PROPERTY_ID)
        .type(BOOLEAN_TYPE)
        .defaultValue("false")
        .label("restore")
        .helpText("whether to cache (default; false) or restore (true)")
        .add()
        .build();
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public String getDisplayType() {
    return "cache required actions";
  }

  @Override
  public String getHelpText() {
    return "delete required actions from user";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "override";
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public void init(Scope scope) {
    // intentionally empty
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // intentionally empty
  }
}
