// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.events.password;

import lombok.extern.jbosslog.JBossLog;
import lombok.RequiredArgsConstructor;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
@RequiredArgsConstructor
public class UpdatePasswordEventListenerProvider implements EventListenerProvider {

  private final KeycloakSession session;

  @Override
  public void onEvent(Event event) {
    if (event.getType() == EventType.UPDATE_PASSWORD) {
      RealmModel realm = session.realms().getRealm(event.getRealmId());
      UserModel user = session.users().getUserById(realm, event.getUserId());
      // get user password hash
      // get user attribute named 'sync' -> users
      // for each user in users
      //   set password
    }
  }

  @Override
  public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }
}

