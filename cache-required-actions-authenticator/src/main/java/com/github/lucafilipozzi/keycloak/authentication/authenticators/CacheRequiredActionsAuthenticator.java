// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class CacheRequiredActionsAuthenticator implements Authenticator {
  public static final String RESTORE_PROPERTY_ID = "restore";

  private static final String ATTRIBUTE_NAME = "required-actions";

  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig != null) {
      UserModel user = context.getUser();
      boolean restore =
          Boolean.parseBoolean(
              authenticatorConfig.getConfig().getOrDefault(RESTORE_PROPERTY_ID, "false"));
      if (restore) {
        user.getAttributeStream(ATTRIBUTE_NAME)
            .collect(Collectors.toSet())
            .forEach(user::addRequiredAction);
        user.removeAttribute(ATTRIBUTE_NAME);
      } else { // cache
        Set<String> newRequiredActions =
            user.getRequiredActionsStream().collect(Collectors.toSet());
        Set<String> oldRequiredActions =
            user.getAttributeStream(ATTRIBUTE_NAME).collect(Collectors.toSet());
        user.setAttribute(
            ATTRIBUTE_NAME,
            List.copyOf(
                Stream.concat(newRequiredActions.stream(), oldRequiredActions.stream())
                    .filter(Objects::nonNull)
                    .filter(Predicate.not(String::isBlank))
                    .collect(Collectors.toSet())));
        newRequiredActions.forEach(user::removeRequiredAction);
      }
    }
    context.success();
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // intentionally empty
  }
}
