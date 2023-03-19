// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.browser;

import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequireRoleContext;
import com.github.lucafilipozzi.keycloak.authentication.authenticators.RequiredRoleModel;
import com.github.lucafilipozzi.keycloak.authentication.authenticators.TargetedUserModel;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class RequireRoleAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(RequireRoleAuthenticator.class);

  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void authenticate(AuthenticationFlowContext ctx) {
    final RequireRoleContext context = new RequireRoleContext(ctx);
    final RequiredRoleModel requiredRole = RequiredRoleModel.resolveFromContext(context);
    final TargetedUserModel targetedUser = TargetedUserModel.resolveFromContext(context);

    if (requiredRole == null || targetedUser == null) {
      Response response = context.form().setError("Server Misconfiguration").createErrorPage(Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
      LOG.info("authenticator misconfigured");
      return;
    }

    LOG.infof("checking whether user '%s' has role '%s'", targetedUser.getUsername(), requiredRole.getName());
    if (targetedUser.hasRequiredRole(requiredRole)) {
      context.success();
      LOG.info("access granted");
      return;
    }

    Response response = context.form().setError("Access Denied").createErrorPage(Status.FORBIDDEN);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
    LOG.info("access denied");
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
