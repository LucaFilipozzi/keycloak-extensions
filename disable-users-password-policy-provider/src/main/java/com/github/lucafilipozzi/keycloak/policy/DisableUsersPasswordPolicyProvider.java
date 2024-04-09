// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.policy;

import lombok.NoArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

@JBossLog
@NoArgsConstructor
public class DisableUsersPasswordPolicyProvider implements PasswordPolicyProvider {
  private static final PolicyError NO_ERROR = null;

  @Override
  public PolicyError validate(RealmModel realm, UserModel user, String password) {
    return NO_ERROR;
  }

  @Override
  public PolicyError validate(String user, String password) {
    return NO_ERROR;
  }

  @Override
  public Object parseConfig(String value) {
    if (StringUtils.isEmpty(value)) {
      throw new PasswordPolicyConfigException("value must not be empty");
    }

    if (!StringUtils.isNumeric(value)) {
      throw new PasswordPolicyConfigException("value must be a number");
    }

    return NumberUtils.toInt(value);
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
