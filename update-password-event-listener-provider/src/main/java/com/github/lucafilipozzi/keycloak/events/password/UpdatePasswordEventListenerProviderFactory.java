// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.events.password;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(EventListenerProviderFactory.class)
public class UpdatePasswordEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "update-password";

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new UpdatePasswordEventListenerProvider(session);
  }

  @Override
  public void init(Config.Scope config) {
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
