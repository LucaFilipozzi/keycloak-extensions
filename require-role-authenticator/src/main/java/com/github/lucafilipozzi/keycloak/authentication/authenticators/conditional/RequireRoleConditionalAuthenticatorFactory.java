// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;

import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequireRoleConstants;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class RequireRoleConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory {
  public static final String PROVIDER_ID = "conditional-require-role";

  private static final Requirement[] REQUIREMENT_CHOICES = {REQUIRED, DISABLED};

  private static final RequireRoleConditionalAuthenticator SINGLETON =
      new RequireRoleConditionalAuthenticator();

  @Override
  public void close() {
    // intentionally empty
  }

  @SuppressFBWarnings
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return RequireRoleConstants.CONFIG_PROPERTIES;
  }

  @Override
  public String getDisplayType() {
    return "Condition - Require Role";
  }

  @Override
  public String getHelpText() {
    return "checkes whether the user (or impersonator) to have the specified role (or a role composited from it)";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @SuppressFBWarnings
  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @SuppressFBWarnings
  @Override
  public RequireRoleConditionalAuthenticator getSingleton() {
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
