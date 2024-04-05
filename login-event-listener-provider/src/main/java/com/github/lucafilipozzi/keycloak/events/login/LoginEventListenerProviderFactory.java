// Copyright 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.events.login;

import static com.github.lucafilipozzi.keycloak.events.login.LoginEventListenerProvider.ATTRIBUTE_NAME;
import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.lang.math.NumberUtils;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.timer.TimerProvider;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class LoginEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "login-event-listener";
  private static final long EXPIRED_PASSWORD_GRACE_PERIOD = 60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  private static final long INACTIVE_ACCOUNT_GRACE_PERIOD = 60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  private static final long INTERVAL = 15 * 1000L; // 15 seconds in milliseconds TODO

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LoginEventListenerProvider(session, Logger.getLogger("org.keycloak.events"));
  }

  @Override
  public void init(Config.Scope config) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
      event -> {
        if (event instanceof PostMigrationEvent) {
          KeycloakSession session = factory.create();
          TimerProvider timer = session.getProvider(TimerProvider.class);
          timer.scheduleTask(this::disableUsers, INTERVAL, "disable-users-task");
        }
      }
    );
  }

  @Override
  public void close() {
    // intentionally empty
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  private void disableUsers(KeycloakSession session) {
    PasswordCredentialProvider passwordCredentialProvider = (PasswordCredentialProvider) session
      .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
    long currentTimeMillis = Time.currentTimeMillis();
    session.realms().getRealmsStream().forEach(
      realm -> {
        if (realm.getEventsListenersStream().anyMatch(n -> n.equals(PROVIDER_ID))) {
          session.users().getUsersStream(realm).forEach(
            user -> {
              CredentialModel password = passwordCredentialProvider.getPassword(realm, user);
              if (password != null && ((currentTimeMillis - password.getCreatedDate()) > EXPIRED_PASSWORD_GRACE_PERIOD) && user.isEnabled()) {
                LOG.warnf("disabled realm='%s' user='%s' userId='%s' because expired password", realm.getName(), user.getUsername(), user.getId());
                user.setEnabled(false);
              }
              String lastLogin = user.getFirstAttribute(ATTRIBUTE_NAME);
              if (NumberUtils.isNumber(lastLogin) && ((currentTimeMillis - NumberUtils.toLong(lastLogin)) > INACTIVE_ACCOUNT_GRACE_PERIOD) && user.isEnabled()) {
                LOG.warnf("disabled realm='%s' user='%s' userId='%s' because inactive account", realm.getName(), user.getUsername(), user.getId());
                user.setEnabled(false);
              }
            }
          );
        }
      }
    );
  }
}
