// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

@AutoService(AuthenticatorFactory.class)
public class RequireImpersonationConditionalAuthenticatorFactory
    implements ConditionalAuthenticatorFactory {
  public static final String PROVIDER_ID = "conditional-require-impersonation";

  private static final Requirement[] REQUIREMENT_CHOICES = {
    Requirement.REQUIRED, Requirement.DISABLED
  };

  private static final RequireImpersonationConditionalAuthenticator SINGLETON =
      new RequireImpersonationConditionalAuthenticator();

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    CONFIG_PROPERTIES =
        ProviderConfigurationBuilder.create()
            .property()
            .name(RequireImpersonationConditionalAuthenticator.NEGATE_RESULT)
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .label("negate result")
            .helpText("Specify whether to negate the result.")
            .defaultValue(false)
            .add()
            .build();
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public String getDisplayType() {
    return "Condition - Require Impersonation";
  }

  @Override
  public String getHelpText() {
    return "checkes whether the user is an impersonator";
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
  public RequireImpersonationConditionalAuthenticator getSingleton() {
    return SINGLETON;
  }

  @Override
  public void init(Scope scope) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory actory) {
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
