// Copyright 2023 Luca Filipozzi. Some rights reserved.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.services.messages.Messages;

public class CustomUsernamePasswordForm extends UsernamePasswordForm {

  @Override
  protected String disabledByBruteForceError() {
    return Messages.ACCOUNT_DISABLED;
  }
}

