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
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.timer.TimerProvider;

import java.util.ArrayList;
import java.util.List;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class LoginEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "login-event-listener";
  private static final long EXPIRED_PASSWORD_GRACE_PERIOD = 60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  private static final long INACTIVE_ACCOUNT_GRACE_PERIOD = 60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  private static final long INTERVAL = 24 * 60 * 60 * 1000L; // 1 day in milliseconds
  private static final List<String> realmIdList = new ArrayList<>();
  private static final Logger logger = Logger.getLogger("org.keycloak.events");

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    String realmId = session.getContext().getRealm().getId();
    LOG.warnf("adding %s to realmIdList", realmId);
    realmIdList.add(realmId);
    return new LoginEventListenerProvider(session, logger);
  }

  @Override
  public void init(Config.Scope config) {
    // intentionally empty
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // schedule task after last ProviderEvent (PostMigrationEvent) has been triggered
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
    PasswordCredentialProvider passwordCredentialProvider = (PasswordCredentialProvider) session.getProvider(CredentialProvider.class);
    long currentTimeMillis = Time.currentTimeMillis();
    realmIdList.forEach(
      realmId -> {
        RealmModel realm = session.realms().getRealm(realmId);
        session.users().getUsersStream(realm).forEach(
          user -> {
            CredentialModel password = passwordCredentialProvider.getPassword(realm, user);
            if (password != null && ((currentTimeMillis - password.getCreatedDate()) > EXPIRED_PASSWORD_GRACE_PERIOD)) {
              LOG.warnf("user '%s' disabled because expired password", user.getUsername());
              // TODO user.setEnabled(false)
            }
            String lastLoginMillis = user.getFirstAttribute(ATTRIBUTE_NAME);
            if (NumberUtils.isNumber(lastLoginMillis) && ((currentTimeMillis - Long.parseLong(lastLoginMillis)) > INACTIVE_ACCOUNT_GRACE_PERIOD)) {
              LOG.warnf("user '%s' disabled because inactive account", user.getUsername());
              // TODO user.setEnabled(false)
            }
         }
        );
      }
    );
  }
}
