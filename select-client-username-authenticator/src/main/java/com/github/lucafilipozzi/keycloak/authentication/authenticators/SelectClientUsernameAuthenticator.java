// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import com.google.common.base.Strings;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import lombok.NonNull;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

@JBossLog
public class SelectClientUsernameAuthenticator implements Authenticator {
  public static final String USER_SESSION_NOTE_KEY = "CLIENT_USERNAME";

  private Set<String> getAvailableClientUsernames(AuthenticationFlowContext context) {
    ClientModel client = context.getAuthenticationSession().getClient();
    UserModel user = context.getUser();
    return user.getAttributeStream(client.getClientId())
        .filter(Predicate.not(String::isBlank))
        .collect(Collectors.toSet());
  }

  @Override
  public void action(@NonNull AuthenticationFlowContext context) { // process form
    Set<String> availableClientUsernames = getAvailableClientUsernames(context);
    String selectedClientUsername =
        Strings.nullToEmpty(
            context.getHttpRequest().getDecodedFormParameters().getFirst("selectedClientUsername"));
    if (availableClientUsernames.isEmpty()
        || !availableClientUsernames.contains(selectedClientUsername)) {
      authenticate(context);
      return;
    }
    context
        .getAuthenticationSession()
        .setUserSessionNote(USER_SESSION_NOTE_KEY, selectedClientUsername);
    context.success();
  }

  @Override
  public void authenticate(@NonNull AuthenticationFlowContext context) { // display form
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
    if (authenticationSession.getUserSessionNotes().containsKey(USER_SESSION_NOTE_KEY)) {
      context.success(); // FIXME need to understand Post Login flow interaction with Browser flow
      return;
    }
    Set<String> availableClientUsernames = getAvailableClientUsernames(context);
    switch (availableClientUsernames.size()) {
      case 0:
        context.failure(AuthenticationFlowError.ACCESS_DENIED); // FIXME throws an exception
        break;
      case 1:
        authenticationSession.setUserSessionNote(
            USER_SESSION_NOTE_KEY, availableClientUsernames.iterator().next());
        context.success();
        break;
      default:
        Response response =
            context
                .form()
                .setAttribute("availableClientUsernames", availableClientUsernames)
                .createForm("select-client-username.ftl");
        context.challenge(response);
        break;
    }
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
