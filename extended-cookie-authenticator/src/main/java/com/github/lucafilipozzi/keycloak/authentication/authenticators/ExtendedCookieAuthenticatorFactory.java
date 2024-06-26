// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.ALTERNATIVE;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;

import com.google.auto.service.AutoService;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Collections;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class ExtendedCookieAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "extended-cookie-authenticator";

  private static final Requirement[] REQUIREMENT_CHOICES = {REQUIRED, ALTERNATIVE, DISABLED};

  private static final ExtendedCookieAuthenticator SINGLETON = new ExtendedCookieAuthenticator();

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
    return Collections.emptyList();
  }

  @Override
  public String getDisplayType() {
    return "Extended Cookie";
  }

  @Override
  public String getHelpText() {
    return "extends Cookie to handle impersonators";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "cookie";
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
    return false;
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
