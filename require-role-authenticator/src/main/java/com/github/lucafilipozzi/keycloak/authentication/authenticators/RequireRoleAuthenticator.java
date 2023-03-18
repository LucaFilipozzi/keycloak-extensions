// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

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
    final EmbellishedAuthFlowContext ctx = new EmbellishedAuthFlowContext(context);
    final RequiredRoleModel requiredRole = resolveRequiredRole(ctx);
    final TargetedUserModel targetedUser = resolveTargetedUser(ctx);

    if (requiredRole == null || targetedUser == null) {
      Response response = ctx.form().setError("Server Misconfiguration").createErrorPage(Status.INTERNAL_SERVER_ERROR);
      ctx.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
      LOG.info("authenticator misconfigured");
      return;
    }

    LOG.infof("checking whether user '%s' has role '%s'", targetedUser.getUsername(), requiredRole.getName());
    if (targetedUser.hasRequiredRole(requiredRole)) {
      ctx.success();
      LOG.info("access granted");
      return;
    }

    Response response = ctx.form().setError("Access Denied").createErrorPage(Status.FORBIDDEN);
    ctx.failure(AuthenticationFlowError.ACCESS_DENIED, response);
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

  private RequiredRoleModel resolveRequiredRole(EmbellishedAuthFlowContext ctx) {
    String requiredRoleName = ctx.getRequiredRoleName();

    if (requiredRoleName == null) {
      return null;
    }

    requiredRoleName = requiredRoleName.trim();

    if (requiredRoleName.isBlank()) {
      return null;
    }

    if (requiredRoleName.startsWith(CLIENT_ID_PLACEHOLDER)) {
      requiredRoleName = requiredRoleName.replace(CLIENT_ID_PLACEHOLDER, ctx.getClient().getClientId());
    }

    RoleModel role = KeycloakModelUtils.getRoleFromString(ctx.getRealm(), requiredRoleName);
    if (role == null) {
      return null;
    }

    return new RequiredRoleModel(ctx, role);
  }

  private TargetedUserModel resolveTargetedUser(EmbellishedAuthFlowContext ctx) {
    TargetedUserModel targetedUser = new TargetedUserModel(ctx, ctx.getUser(), null);

    if (ctx.getApplyToImpersonator()) {
      KeycloakSession session = ctx.getSession();
      RealmModel realm = ctx.getRealm();

      AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
      if (authResult == null) {
        return null;
      }

      UserSessionModel userSession = authResult.getSession();
      Map<String, String> userSessionNotes = userSession.getNotes();
      if (userSessionNotes.containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
        String impersonatorId = userSessionNotes.get(ImpersonationSessionNote.IMPERSONATOR_ID.toString());
        targetedUser = new TargetedUserModel(ctx, session.users().getUserById(realm, impersonatorId), userSession);
      }
    }

    return targetedUser;
  }

  @RequiredArgsConstructor
  private static class EmbellishedAuthFlowContext {
    @Delegate @NonNull
    private final AuthenticationFlowContext context;

    private Boolean applyToImpersonator = null;

    private String requiredRoleName = null;

    private ClientModel client = null;

    private Map<String, String> config = null;

    ClientModel getClient() {
      if (client == null) {
        client = context.getAuthenticationSession().getClient();
      }
      return client;
    }

    Boolean getApplyToImpersonator() {
      if (applyToImpersonator == null) {
        applyToImpersonator = Boolean.parseBoolean(getConfig().get(APPLY_TO_IMPERSONATOR));
      }
      return applyToImpersonator;
    }

    String getRequiredRoleName() {
      if (requiredRoleName == null) {
        requiredRoleName = getConfig().get(REQUIRED_ROLE_NAME);
      }
      return requiredRoleName;
    }

    private Map<String, String> getConfig() {
      if (config == null) {
        config = context.getAuthenticatorConfig().getConfig();
      }
      return config;
    }
  }

  @RequiredArgsConstructor
  private static class TargetedUserModel implements UserModel {
    @NonNull
    private final EmbellishedAuthFlowContext ctx;

    @Delegate @NonNull
    private final UserModel user;

    private final UserSessionModel userSession;

    boolean hasRequiredRole(final RequiredRoleModel requiredRole) {
      if (requiredRole.getApplyToImpersonator()) {
        if (userSession == null) {
          return true; // required role applies to impersonator but impersonation not in effect
        }

        Set<RoleModel> clientRoles = ctx.getClient().getRolesStream()
            .filter(x -> getDeepRoleCompositesStream(x).anyMatch(y -> y.equals(requiredRole)))
            .collect(Collectors.toSet());
        Set<RoleModel> userRoles = RoleUtils.getDeepUserRoleMappings(this);
        Set<RoleModel> roleIntersection = Sets.intersection(clientRoles, userRoles);

        if (!roleIntersection.isEmpty()) {
          String roles = roleIntersection.stream().map(RoleModel::getName).collect(Collectors.joining(","));
          userSession.setNote("IMPERSONATOR_ROLES", roles);
          return true; // targeted user (impersonator) has required role
        }
      } else {
        if (RoleUtils.hasRole(getRoleMappingsStream(), requiredRole)                       // cheap, try first
            || RoleUtils.hasRole(RoleUtils.getDeepUserRoleMappings(this), requiredRole)) { // expensive, try next
          return true; // targeted user has required role
        }
      }
      return false; // targeted user does not have required role
    }

    private static Stream<RoleModel> getDeepRoleCompositesStream(final RoleModel role) { // helper function
      return Stream.concat(Stream.of(role), role.getCompositesStream().flatMap(x -> getDeepRoleCompositesStream(x)));
    }
  }

  @RequiredArgsConstructor
  private static class RequiredRoleModel implements RoleModel {
    @NonNull
    private EmbellishedAuthFlowContext ctx;

    @Delegate @NonNull
    private RoleModel role;

    Boolean getApplyToImpersonator() {
      return ctx.getApplyToImpersonator();
    }
  }
}
