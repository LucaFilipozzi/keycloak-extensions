// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators.browser;

import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequireRoleConstants;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class RequireRoleAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "require-role";

  private static final Requirement[] REQUIREMENT_CHOICES = {
    Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED
  };

  private static final RequireRoleAuthenticator SINGLETON = new RequireRoleAuthenticator();

  @Override
  public void close() {
    // intentionally empty
  }

  @SuppressFBWarnings
  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @SuppressFBWarnings
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return RequireRoleConstants.CONFIG_PROPERTIES;
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

  @SuppressFBWarnings
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
