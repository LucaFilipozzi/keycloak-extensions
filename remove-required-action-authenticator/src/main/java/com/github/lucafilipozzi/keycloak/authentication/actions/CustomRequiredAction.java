// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.actions;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

@JBossLog
public class CustomRequiredAction implements RequiredActionProvider {
  public static final String ID = "UPDATE_CUSTOM_INFO";

  @Override
  public void evaluateTriggers(RequiredActionContext context) {
    LOG.info("evaluateTriggers");
    context.getAuthenticationSession().getExecutionStatus();
    // intentionally empty
  }

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    LOG.info("requiredActionChallenge");
    // intentionally empty
  }

  @Override
  public void processAction(RequiredActionContext context) {
    LOG.info("processAction");
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
