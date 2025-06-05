// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import static jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static jakarta.ws.rs.core.Response.Status.NOT_ACCEPTABLE;
import static org.keycloak.authentication.AuthenticationFlowError.INTERNAL_ERROR;
import static org.keycloak.authentication.AuthenticationFlowError.INVALID_USER;
import static org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE;

import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

@JBossLog
public class UsernamePolicyAuthenticator implements Authenticator {
  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) {
      Response response =
          context.form().setError("Server Misconfiguration").createErrorPage(INTERNAL_SERVER_ERROR);
      context.failureChallenge(INTERNAL_ERROR, response);
      return;
    }
    String pattern = authenticatorConfig.getConfig().get("pattern");

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    SerializedBrokeredIdentityContext serializedCtx =
        SerializedBrokeredIdentityContext.readFromAuthenticationSession(
            authSession, BROKERED_CONTEXT_NOTE);
    String username = serializedCtx.getUsername();

    if (!username.matches(pattern)) {
      Response response =
          context.form().setError("Invalid Username").createErrorPage(NOT_ACCEPTABLE);
      context.failureChallenge(INVALID_USER, response);
      return;
    }

    context.success();
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // intentionally empty
  }
}
