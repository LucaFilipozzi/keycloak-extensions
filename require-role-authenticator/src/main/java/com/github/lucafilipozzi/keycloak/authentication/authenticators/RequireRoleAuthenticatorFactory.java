// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class RequireRoleAuthenticatorFactory implements AuthenticatorFactory {

  private static final Logger LOGGER = Logger.getLogger(RequireRoleAuthenticatorFactory.class);

  public static final String PROVIDER_ID = "require-role";

  public static final RequireRoleAuthenticator SINGLETON = new RequireRoleAuthenticator();

  public static final Requirement[] REQUIREMENT_CHOICES = { Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED };

  private static final List<ProviderConfigProperty> configProperties;

  static {
    configProperties = ProviderConfigurationBuilder.create()
      .property()
        .name(RequireRoleAuthenticator.APPLY_TO_IMPERSONATOR)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("apply to impersonator")
        .helpText("Specify whether to apply the role requirement to the user (default; off) or to the impersonator (on).")
        .defaultValue(false)
      .add()
      .property()
        .name(RequireRoleAuthenticator.REQUIRED_ROLE_NAME)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("required role name")
        .helpText("Specify the name of the role that a user is required to have for successful authentication. "
            + "This can be a realm or client role. Client roles have the form 'clientId.roleName' for a specific client. "
            + "Alternately, the expression '${clientId}.roleName' may be used to specify a role of the current client. "
            + "Note that if the required role name does not resolve to a role, then the authentication will fail. "
            + "Note further that requiring a role of an impersonator must only be configured in browser/cookie flows.")
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
    return configProperties;
  }

  @Override
  public String getDisplayType() {
    return "Require Role";
  }

  @Override
  public String getHelpText() {
    return "requires the user (or impersonator) to have the specified role (or a role composited from it)";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public void init(Config.Scope config) {
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
