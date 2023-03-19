// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.conditional;

import com.google.common.collect.Sets;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import lombok.experimental.Helper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

public class RequireRoleConditionalAuthenticator implements ConditionalAuthenticator {

  private static final Logger LOG = Logger.getLogger(RequireRoleConditionalAuthenticator.class);

  public static final String REQUIRED_ROLE_NAME = "roleName";

  public static final String APPLY_TO_IMPERSONATOR = "applyToImpersonator";

  private static final String CLIENT_ID_PLACEHOLDER = "${clientId}";

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
    // TODO
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
