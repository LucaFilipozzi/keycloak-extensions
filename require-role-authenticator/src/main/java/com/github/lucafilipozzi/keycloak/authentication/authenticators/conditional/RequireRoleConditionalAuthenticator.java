// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequireRoleContext;
import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequiredRoleModel;
import com.github.lucafilipozzi.keycloak.authentication.authenticators.TargetedUserModel;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class RequireRoleConditionalAuthenticator implements ConditionalAuthenticator {
  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public boolean matchCondition(AuthenticationFlowContext ctx) {
    final RequireRoleContext context = new RequireRoleContext(ctx);
    final RequiredRoleModel requiredRole = RequiredRoleModel.resolveFromContext(context);
    final TargetedUserModel targetedUser = TargetedUserModel.resolveFromContext(context);

    if (requiredRole == null || targetedUser == null) {
      LOG.info("conditional authenticator misconfigured");
      return false;
    }

    LOG.infof(
        "checking whether user '%s' has role '%s'",
        targetedUser.getUsername(), requiredRole.getName());
    boolean result = targetedUser.hasRequiredRole(requiredRole);
    if (context.getNegateResult().equals(Boolean.TRUE)) {
      LOG.info("negating result");
      result = !result;
    }

    if (result) {
      LOG.info("condition met");
      return true;
    }

    LOG.info("condition not met");
    return false;
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
