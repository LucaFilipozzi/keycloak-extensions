// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import java.util.List;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class RequireRoleConstants {
  public static final String REQUIRED_ROLE_NAME = "roleName";

  public static final String APPLY_TO_IMPERSONATOR = "applyToImpersonator";

  public static final String CLIENT_ID_PLACEHOLDER = "${clientId}";

  public static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
      .property()
        .name(APPLY_TO_IMPERSONATOR)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("apply to impersonator")
        .helpText("Specify whether to apply the role requirement to the user (default; off) or to the impersonator (on).")
        .defaultValue(false)
      .add()
      .property()
        .name(REQUIRED_ROLE_NAME)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("required role name")
        .helpText("Specify the name of the role that a user is required to have for successful authentication. "
            + "This can be a realm or client role. Client roles have the form 'clientId.roleName' for a specific client. "
            + "Alternately, the expression '${clientId}.roleName' may be used to specify a role of the current client. "
            + "Note that if the required role name does not resolve to a role, then the authentication will fail. "
            + "Note further that requiring a role of an impersonator must only be configured in browser/cookie flows.")
      .add()
      .build();
  }
}
