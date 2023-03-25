// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class SelectClientUsernameAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "select-client-username-authenticator";

  private static final Requirement[] REQUIREMENT_CHOICES = { REQUIRED, DISABLED };

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new SelectClientUsernameAuthenticator();
  }

  @Override
  public String getDisplayType() {
    return "select client username form";
  }

  @Override
  public String getHelpText() {
    return "ask user to select client username";
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
  public void init(Scope config) {
    // intentionally empty
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // intentionally empty
  }
}
