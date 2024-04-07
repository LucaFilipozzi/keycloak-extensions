// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import com.google.common.collect.Sets;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

@RequiredArgsConstructor
public class TargetedUserModel implements UserModel {
  @NonNull private final RequireRoleContext context;

  @Delegate @NonNull private final UserModel user;

  private final UserSessionModel userSession;

  public static TargetedUserModel resolveFromContext(RequireRoleContext context) {
    TargetedUserModel targetedUser = new TargetedUserModel(context, context.getUser(), null);

    if (context.getApplyToImpersonator().equals(Boolean.TRUE)) {
      KeycloakSession session = context.getSession();
      RealmModel realm = context.getRealm();

      AuthResult authResult =
          AuthenticationManager.authenticateIdentityCookie(session, realm, true);
      if (authResult == null) {
        return null;
      }

      UserSessionModel userSession = authResult.getSession();
      Map<String, String> userSessionNotes = userSession.getNotes();
      if (userSessionNotes.containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
        String impersonatorId =
            userSessionNotes.get(ImpersonationSessionNote.IMPERSONATOR_ID.toString());
        targetedUser =
            new TargetedUserModel(
                context, session.users().getUserById(realm, impersonatorId), userSession);
      }
    }

    return targetedUser;
  }

  public boolean hasRequiredRole(final RequiredRoleModel requiredRole) {
    if (requiredRole.getApplyToImpersonator().equals(Boolean.TRUE)) {
      if (userSession == null) { // impersonation is not active
        return !context.getEnforceStrictly();
      }

      Set<RoleModel> clientRoles =
          context
              .getClient()
              .getRolesStream()
              .filter(x -> getDeepRoleCompositesStream(x).anyMatch(y -> y.equals(requiredRole)))
              .collect(Collectors.toSet());
      Set<RoleModel> userRoles = RoleUtils.getDeepUserRoleMappings(this);
      Set<RoleModel> roleIntersection = Sets.intersection(clientRoles, userRoles);

      if (!roleIntersection.isEmpty()) {
        String roles =
            roleIntersection.stream().map(RoleModel::getName).collect(Collectors.joining(","));
        userSession.setNote("IMPERSONATOR_ROLES", roles);
        return true; // targeted user (impersonator) has required role
      }
    } else {
      return RoleUtils.hasRole(getRoleMappingsStream(), requiredRole) // cheap, try first
          || RoleUtils.hasRole(
              RoleUtils.getDeepUserRoleMappings(this), requiredRole); // expensive, try next
    }
    return false; // targeted user does not have required role
  }

  private static Stream<RoleModel> getDeepRoleCompositesStream(
      final RoleModel role) { // helper function
    return Stream.concat(
        Stream.of(role),
        role.getCompositesStream().flatMap(TargetedUserModel::getDeepRoleCompositesStream));
  }
}
