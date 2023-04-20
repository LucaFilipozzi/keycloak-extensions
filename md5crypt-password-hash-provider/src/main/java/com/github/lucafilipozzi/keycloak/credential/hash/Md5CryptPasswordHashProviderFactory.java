// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.credential.hash;

import org.keycloak.Config.Scope;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class Md5CryptPasswordHashProviderFactory implements PasswordHashProviderFactory {
  public static final String PROVIDER_ID = "md5-crypt";

  @Override
  public PasswordHashProvider create(KeycloakSession session) {
    return new Md5CryptPasswordHashProvider();
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
    return PROVIDER_ID;
  }
}
