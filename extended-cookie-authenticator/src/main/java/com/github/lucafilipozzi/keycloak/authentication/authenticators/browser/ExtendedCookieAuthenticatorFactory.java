// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.browser;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class ExtendedCookieAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "extended-cookie-authenticator";

  private static final Requirement[] REQUIREMENT_CHOICES = { Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED };

  private static final ExtendedCookieAuthenticator SINGLETON = new ExtendedCookieAuthenticator();

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
      .property()
        .name(ExtendedCookieAuthenticator.FORCE_REAUTHENTICATION)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("force reauthentication")
        .helpText("Specify whether to force the user to reauthenticate.")
        .defaultValue(false)
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
    return "Extended Cookie";
  }

  @Override
  public String getHelpText() {
    return "Extends Cookie to handle impersonators.";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "cookie";
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
