// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.
//
// inspirations:
// - github.com/keycloak/keycloak:
//   - services/src/main/java/org/keycloak/authentication/authenticators/conditional/ConditionalRoleAuthenticator.java
// - github.com/thomasdarimont/keycloak-extension-playground
//   - auth-require-role-extension/src/main/java/com/github/thomasdarimont/keycloak/auth/requirerole/RequireRoleAuthenticator.java
//
// primary differences:
// - not a conditional authenticator
// - role requirement can be applied to impersonator

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import java.util.Map;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

public class RequireRoleAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(RequireRoleAuthenticator.class);

  public static final String REQUIRED_ROLE_NAME = "roleName";

  public static final String APPLY_TO_IMPERSONATOR = "applyToImpersonator";

  private static final String CLIENT_ID_PLACEHOLDER = "${clientId}";

  @Override
  public void action(AuthenticationFlowContext context) {
    // intentionally empty
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    RoleModel requiredRole = resolveRequiredRole(context);
    UserModel targetedUser = resolveTargetedUser(context);

    if (targetedUser == null || requiredRole == null) {
      Response response = context.form()
          .setError("Server Misconfiguration")
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
      return;
    }

    if (userHasRole(context, targetedUser, requiredRole)) {
      context.success();
      return;
    }

    Response response = context.form()
        .setError("Access Denied")
        .createErrorPage(Response.Status.FORBIDDEN);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
  }

  private RoleModel resolveRequiredRole(AuthenticationFlowContext context) {
    Map<String, String> config = context.getAuthenticatorConfig().getConfig();
    String requiredRoleName = config.get(REQUIRED_ROLE_NAME);

    if (requiredRoleName == null) {
      return null;
    }

    requiredRoleName = requiredRoleName.trim();

    if (requiredRoleName.isBlank()) {
      return null;
    }

    if (requiredRoleName.startsWith(CLIENT_ID_PLACEHOLDER)) {
      ClientModel client = context.getAuthenticationSession().getClient();
      requiredRoleName = requiredRoleName.replace(CLIENT_ID_PLACEHOLDER, client.getClientId());
    }

    RealmModel realm = context.getRealm();
    return KeycloakModelUtils.getRoleFromString(realm, requiredRoleName);
  }

  private UserModel resolveTargetedUser(AuthenticationFlowContext context) {
    Map<String, String> config = context.getAuthenticatorConfig().getConfig();
    RealmModel realm = context.getRealm();
    KeycloakSession session = context.getSession();
    UserModel targetedUser = context.getUser();
    Boolean applyToImpersonator = Boolean.parseBoolean(config.get(APPLY_TO_IMPERSONATOR));

    if (applyToImpersonator) {
      AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
      if (authResult == null) {
        return null;
      }

      Map<String, String> userSessionNotes = authResult.getSession().getNotes();
      if (userSessionNotes.containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
        String impersonatorId = userSessionNotes.get(ImpersonationSessionNote.IMPERSONATOR_ID.toString());
        targetedUser = session.users().getUserById(realm, impersonatorId);
      }
    }

    return targetedUser;
  }

  private boolean userHasRole(AuthenticationFlowContext context, UserModel targetedUser, RoleModel requiredRole) {
    Map<String, String> config = context.getAuthenticatorConfig().getConfig();
    Boolean applyToImpersonator = Boolean.parseBoolean(config.get(APPLY_TO_IMPERSONATOR));

    LOG.debugf("determining whether user '%s' has role '%s'", targetedUser.getUsername(), requiredRole.getName());

    // return true if rule requirement applies to impersonator but impersonation is not active
    if (applyToImpersonator && targetedUser == context.getUser()) {
      LOG.debug("access granted - impersonation is not active");
      return true;
    }

    // rely on short-circuit evaluation to potentially avoid expensive call
    if (RoleUtils.hasRole(targetedUser.getRoleMappingsStream(), requiredRole) /* cheap */
        || RoleUtils.hasRole(RoleUtils.getDeepUserRoleMappings(targetedUser), requiredRole) /* expensive */) {
      LOG.debug("access granted - user does have role");
      return true;
    }

    LOG.debug("access denied - user does not have role");
    return false;
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
