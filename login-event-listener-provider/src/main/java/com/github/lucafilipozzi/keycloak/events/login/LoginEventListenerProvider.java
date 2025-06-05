// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.events.login;

import lombok.extern.jbosslog.JBossLog;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.log.JBossLoggingEventListenerProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class LoginEventListenerProvider extends JBossLoggingEventListenerProvider
    implements EventListenerProvider {
  public final KeycloakSession session;
  public static final String LAST_LOGIN_ATTRIBUTE_NAME = "last-login";

  public LoginEventListenerProvider(KeycloakSession session, Logger logger) {
    super(session, logger, Logger.Level.WARN, Logger.Level.WARN, null, false, false);
    this.session = session;
  }

  @Override
  public void onEvent(Event event) {
    if (event.getType() == EventType.LOGIN) {
      RealmModel realm = session.realms().getRealm(event.getRealmId());
      UserModel user = session.users().getUserById(realm, event.getUserId());
      LOG.tracef(
          "setting %s on realm='%s' user='%s' userId='%s'",
          LAST_LOGIN_ATTRIBUTE_NAME, realm.getName(), user.getUsername(), user.getId());
      user.setSingleAttribute(LAST_LOGIN_ATTRIBUTE_NAME, Long.toString(Time.currentTimeMillis()));
      super.onEvent(event);
    }
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    // intentionally empty
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
