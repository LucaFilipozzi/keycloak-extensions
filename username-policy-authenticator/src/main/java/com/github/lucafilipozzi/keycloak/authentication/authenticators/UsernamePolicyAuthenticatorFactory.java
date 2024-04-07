// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.ALTERNATIVE;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;

import com.google.auto.service.AutoService;
import java.util.List;
import lombok.NonNull;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

@AutoService(AuthenticatorFactory.class)
public class UsernamePolicyAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "username-policy-authenticator";

  private static final Requirement[] REQUIREMENT_CHOICES = {REQUIRED, ALTERNATIVE, DISABLED};

  private static final UsernamePolicyAuthenticator SINGLETON = new UsernamePolicyAuthenticator();

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    CONFIG_PROPERTIES =
        ProviderConfigurationBuilder.create()
            .property()
            .name("pattern")
            .type(ProviderConfigProperty.STRING_TYPE)
            .label("pattern")
            .helpText("provide pattern to validate against")
            .add()
            .build();
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public Authenticator create(@NonNull KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public String getDisplayType() {
    return "username policy enforcement";
  }

  @Override
  public String getHelpText() {
    return "specify the patterns to enforce on incoming usernames";
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
