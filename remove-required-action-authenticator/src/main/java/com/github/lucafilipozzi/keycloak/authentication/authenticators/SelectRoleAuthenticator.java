// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import com.google.common.base.Strings;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import lombok.NonNull;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class SelectRoleAuthenticator implements Authenticator {
  public static final String USER_SESSION_NOTE_ID = "SELECTED_ROLE";

  private Set<String> getAvailableRoles(AuthenticationFlowContext context) {
    ClientModel client = context.getAuthenticationSession().getClient();
    UserModel user = context.getUser();
    return user.getAttributeStream(client.getClientId()).filter(Predicate.not(String::isBlank)).collect(Collectors.toSet());
  }

  @Override
  public void action(@NonNull AuthenticationFlowContext context) { // process form
    Set<String> availableRoles = getAvailableRoles(context);
    String selectedRole = Strings.nullToEmpty(context.getHttpRequest().getDecodedFormParameters().getFirst("selectedRole"));

    if (availableRoles.isEmpty() || !availableRoles.contains(selectedRole)) {
      LOG.info("action: availableRoles does not contain selectedRole");
      authenticate(context); // TODO error message
      return;
    }

    LOG.infof("action: selectedRole=%s", selectedRole);
    context.getAuthenticationSession().setUserSessionNote(USER_SESSION_NOTE_ID, selectedRole);
    context.success();
  }

  @Override
  public void authenticate(@NonNull AuthenticationFlowContext context) { // display form
    Set<String> availableRoles = getAvailableRoles(context);
    switch (availableRoles.size()) {
      case 0:
        context.attempted(); // TODO should fail
        break;
      case 1:
        context.getAuthenticationSession().setUserSessionNote(USER_SESSION_NOTE_ID, availableRoles.iterator().next());
        context.success();
        break;
      default:
        Response response = context.form().setAttribute("availableRoles", availableRoles).createForm("select-role.ftl");
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
