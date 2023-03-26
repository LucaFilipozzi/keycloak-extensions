// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

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
  private static final String PREFIX = "DEFER_";

  private static final int LENGTH = PREFIX.length();

  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    boolean restore = false;
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig != null) {
      restore = Boolean.parseBoolean(authenticatorConfig.getConfig()
          .getOrDefault(RESTORE_PROPERTY_ID, "false"));
    }

    UserModel user = context.getUser();
    if (restore) {
      user.getAttributes().keySet().stream()
          .filter(attribute -> attribute.startsWith(PREFIX))
          .forEach(attribute -> {
            user.removeAttribute(attribute);
            user.addRequiredAction(attribute.substring(LENGTH)); } );
    } else { // cache
      user.getRequiredActionsStream()
          .forEach(requiredAction -> {
            user.removeRequiredAction(requiredAction);
            user.setSingleAttribute(PREFIX + requiredAction, "N/A"); } );
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
