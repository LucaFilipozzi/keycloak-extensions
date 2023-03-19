// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

public class RequireImpersonationConditionalAuthenticator implements ConditionalAuthenticator {
  private static final Logger LOG = Logger.getLogger(RequireImpersonationConditionalAuthenticator.class);

  public static String NEGATE_RESULT = "negateResult";

  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    boolean negateResult = Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get(NEGATE_RESULT));
    AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(), context.getRealm(), true);
    if (authResult != null && authResult.getSession().getNotes().containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
      return negateResult ? false : true;
    }
    return negateResult ? true : false;
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
