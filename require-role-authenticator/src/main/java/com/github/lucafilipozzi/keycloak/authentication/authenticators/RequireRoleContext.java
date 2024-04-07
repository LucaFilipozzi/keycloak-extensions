// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import java.util.Map;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.ClientModel;

@RequiredArgsConstructor
public class RequireRoleContext {
  @Delegate @NonNull private final AuthenticationFlowContext context;

  private Boolean applyToImpersonator = null;

  private Boolean enforceStrictly = null;

  private Boolean negateResult = null;

  private String requiredRoleName = null;

  private ClientModel client = null;

  private Map<String, String> config = null;

  public ClientModel getClient() {
    if (client == null) {
      client = context.getAuthenticationSession().getClient();
    }
    return client;
  }

  public Boolean getApplyToImpersonator() {
    if (applyToImpersonator == null) {
      applyToImpersonator =
          Boolean.parseBoolean(getConfig().get(RequireRoleConstants.APPLY_TO_IMPERSONATOR));
    }
    return applyToImpersonator;
  }

  public Boolean getEnforceStrictly() {
    if (enforceStrictly == null) {
      enforceStrictly =
          Boolean.parseBoolean(getConfig().get(RequireRoleConstants.ENFORCE_STRICTLY));
    }
    return enforceStrictly;
  }

  public Boolean getNegateResult() {
    if (negateResult == null) {
      negateResult = Boolean.parseBoolean(getConfig().get(RequireRoleConstants.NEGATE_RESULT));
    }
    return negateResult;
  }

  public String getRequiredRoleName() {
    if (requiredRoleName == null) {
      requiredRoleName = getConfig().get(RequireRoleConstants.REQUIRED_ROLE_NAME);
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
