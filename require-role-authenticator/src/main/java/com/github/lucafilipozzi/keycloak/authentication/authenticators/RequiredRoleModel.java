// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;

@RequiredArgsConstructor
public class RequiredRoleModel implements RoleModel {
  @NonNull
  private RequireRoleContext context;

  @Delegate @NonNull
  private RoleModel role;

  Boolean getApplyToImpersonator() {
    return context.getApplyToImpersonator();
  }

  public static RequiredRoleModel resolveFromContext(RequireRoleContext context) {
    String requiredRoleName = context.getRequiredRoleName();

    if (requiredRoleName == null) {
      return null;
    }

    requiredRoleName = requiredRoleName.trim();

    if (requiredRoleName.isBlank()) {
      return null;
    }

    if (requiredRoleName.startsWith(RequireRoleConstants.CLIENT_ID_PLACEHOLDER)) {
      requiredRoleName = requiredRoleName.replace(
          RequireRoleConstants.CLIENT_ID_PLACEHOLDER,
          context.getClient().getClientId());
    }

    RoleModel role = KeycloakModelUtils.getRoleFromString(context.getRealm(), requiredRoleName);
    if (role == null) {
      return null;
    }

    return new RequiredRoleModel(context, role);
  }
}
