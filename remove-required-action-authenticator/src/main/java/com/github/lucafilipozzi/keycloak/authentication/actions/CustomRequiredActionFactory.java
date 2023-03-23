// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.actions;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@JBossLog
public class CustomRequiredActionFactory implements RequiredActionFactory {
  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return new CustomRequiredAction();
  }

  @Override
  public void init(Scope config) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public String getId() {
    return CustomRequiredAction.ID;
  }

  @Override
  public String getDisplayText() {
    return "update custom info";
  }
}
