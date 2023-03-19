// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class RequireRoleConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory {
  private static final Logger LOGGER = Logger.getLogger(RequireRoleConditionalAuthenticatorFactory.class);

  public static final String PROVIDER_ID = "conditional-require-role";

  public static final RequireRoleConditionalAuthenticator SINGLETON = new RequireRoleConditionalAuthenticator();

  private static final Requirement[] REQUIREMENT_CHOICES = { Requirement.REQUIRED, Requirement.DISABLED };

  private static final List<ProviderConfigProperty> configProperties;

  static {
    configProperties = ProviderConfigurationBuilder.create()
      .property()
        .name(RequireRoleConditionalAuthenticator.APPLY_TO_IMPERSONATOR)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("apply to impersonator")
        .helpText("Specify whether to apply the role requirement to the user (default; off) or to the impersonator (on).")
        .defaultValue(false)
      .add()
      .property()
        .name(RequireRoleConditionalAuthenticator.REQUIRED_ROLE_NAME)
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
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public String getDisplayType() {
    return "Condition - Require Role";
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
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public RequireRoleConditionalAuthenticator getSingleton() {
    return SINGLETON;
  }

  @Override
  public void init(Scope config) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
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
}
