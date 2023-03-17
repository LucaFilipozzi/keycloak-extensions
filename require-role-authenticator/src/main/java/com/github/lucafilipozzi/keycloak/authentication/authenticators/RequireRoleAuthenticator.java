// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import com.google.common.collect.Sets;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
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

public class RequireRoleAuthenticator implements Authenticator {

  private class TargetedUserModel {
    private UserModel user = null;
    private UserSessionModel userSession = null;
    private boolean isImpersonator = false;

    public TargetedUserModel(UserModel user, UserSessionModel userSession) {
      this.user = user;
      this.userSession = userSession;
    }

    UserModel getUser() {
      return user;
    }

    UserSessionModel getUserSession() {
      return userSession;
    }

    boolean isImpersonator() {
      return userSession != null;
    }
  }

  private class RequiredRoleModel {
    private RoleModel role = null;
    private boolean isAppliedToImpersonator = false;

    public RequiredRoleModel(RoleModel role, boolean isAppliedToImpersonator) {
      this.role = role;
      this.isAppliedToImpersonator = isAppliedToImpersonator;
    }

    RoleModel getRole() {
      return role;
    }

    boolean isAppliedToImpersonator() {
      return isAppliedToImpersonator;
    }
  }

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
    RequiredRoleModel requiredRole = resolveRequiredRole(context);
    TargetedUserModel targetedUser = resolveTargetedUser(context);

    if (requiredRole == null || targetedUser == null) {
      Response response = context.form()
          .setError("Server Misconfiguration")
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
      return;
    }

    if (targetedUserHasRequiredRole(context, targetedUser, requiredRole)) {
      context.success();
      return;
    }

    Response response = context.form()
        .setError("Access Denied")
        .createErrorPage(Response.Status.FORBIDDEN);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
  }

  private RequiredRoleModel resolveRequiredRole(AuthenticationFlowContext context) {
    String requiredRoleName = getRequiredRoleName(context);

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

    RoleModel role = KeycloakModelUtils.getRoleFromString(context.getRealm(), requiredRoleName);
    if (role == null) {
      return null;
    }

    return new RequiredRoleModel(role, isAppliedToImpersonator(context));
  }

  private TargetedUserModel resolveTargetedUser(AuthenticationFlowContext context) {
    RealmModel realm = context.getRealm();
    KeycloakSession session = context.getSession();
    TargetedUserModel targetedUser = new TargetedUserModel(context.getUser(), null);

    if (isAppliedToImpersonator(context)) {
      AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
      if (authResult == null) {
        return null;
      }

      UserSessionModel userSession = authResult.getSession();
      Map<String, String> userSessionNotes = userSession.getNotes();
      if (userSessionNotes.containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
        String impersonatorId = userSessionNotes.get(ImpersonationSessionNote.IMPERSONATOR_ID.toString());
        targetedUser = new TargetedUserModel(session.users().getUserById(realm, impersonatorId), userSession);
      }
    }

    return targetedUser;
  }

  private String getRequiredRoleName(AuthenticationFlowContext context) {
    return context.getAuthenticatorConfig().getConfig().get(REQUIRED_ROLE_NAME);
  }

  private Boolean isAppliedToImpersonator(AuthenticationFlowContext context) {
    return Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get(APPLY_TO_IMPERSONATOR));
  }

  private boolean targetedUserHasRequiredRole(AuthenticationFlowContext context, TargetedUserModel targetedUser, RequiredRoleModel requiredRole) {
    LOG.infof("determining whether user '%s' has role '%s'", targetedUser.getUser().getUsername(), requiredRole.getRole().getName());

    if (requiredRole.isAppliedToImpersonator()) {
      if (!targetedUser.isImpersonator()) {
        LOG.info("access granted to user (impersonation not in effect)");
        return true;
      }

      if (impersonatorHasRole(context, targetedUser, requiredRole)) /* expensive but impersonation is rare */ {
        LOG.info("access granted to impersonator");
        return true;
      }

      LOG.info("access denied to impersonator");
      return false;
    } else {
      if (RoleUtils.hasRole(targetedUser.getUser().getRoleMappingsStream(), requiredRole.getRole()) /* cheap, try first */
          || RoleUtils.hasRole(RoleUtils.getDeepUserRoleMappings(targetedUser.getUser()), requiredRole.getRole()) /* expensive */) {
        LOG.info("access granted to user");
        return true;
      }

      LOG.info("access denied to user");
      return false;
    }
  }

  private boolean impersonatorHasRole(AuthenticationFlowContext context, TargetedUserModel targetedUser, RequiredRoleModel requiredRole) {
    // find all client roles that are either themselves or are composited from, however deeply, the required role
    Set<RoleModel> clientRoles = context.getAuthenticationSession().getClient().getRolesStream()
        .filter(x -> flattenRoleTree(x).anyMatch(y -> y.equals(requiredRole.getRole())))
        .collect(Collectors.toSet());

    // find all user roles, however deeply, including those held via group membership
    Set<RoleModel> userRoles = RoleUtils.getDeepUserRoleMappings(targetedUser.getUser());

    Set<RoleModel> roleIntersection = Sets.intersection(clientRoles, userRoles);

    if (roleIntersection.isEmpty()) {
      return false; // the targeted user (impersonator) does not have the required role
    }

    String roles = roleIntersection.stream().map(RoleModel::getName).collect(Collectors.joining(","));
    targetedUser.getUserSession().setNote("IMPERSONATOR_ROLES", roles);

    return true; // the targeted user (impersonator) does have the required role
  }

  private Stream<RoleModel> flattenRoleTree(final RoleModel role) {
    return Stream.concat(Stream.of(role), role.getCompositesStream().flatMap(x -> flattenRoleTree(x)));
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
