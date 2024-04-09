// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.events.login;

import static com.github.lucafilipozzi.keycloak.events.login.LoginEventListenerProvider.ATTRIBUTE_NAME;

import com.google.auto.service.AutoService;
import java.util.function.Consumer;
import java.util.function.Predicate;
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
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.timer.TimerProvider;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class LoginEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "login-event-listener";

  private static final long DAYS_TO_MILLIS = 86400000L;

  private static final long SECS_TO_MILLIS = 1000L;

  private static final long TASK_INTERVAL = 86400; //  1 day  in seconds

  private long taskInterval;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LoginEventListenerProvider(session, Logger.getLogger("org.keycloak.events"));
  }

  @Override
  public void init(Config.Scope config) {
    taskInterval = config.getLong("taskInterval", TASK_INTERVAL) * SECS_TO_MILLIS;
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
        event -> {
          if (event instanceof PostMigrationEvent) {
            LOG.debug("registering disable-users-task");
            KeycloakSession session = factory.create();
            TimerProvider timer = session.getProvider(TimerProvider.class);
            timer.scheduleTask(this::disableUsers, taskInterval, "disable-users-task");
          }
        });
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
    PasswordCredentialProvider passwordCredentialProvider =
        (PasswordCredentialProvider)
            session.getProvider(
                CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);

    long currentTimeMillis = Time.currentTimeMillis();

    session
        .realms()
        .getRealmsStream()
        .forEach(
            realm -> {
              if (realm.getEventsListenersStream().noneMatch(x -> x.equals(PROVIDER_ID))) {
                LOG.debugf(
                    "realm='%s' does not have 'Login Event Listener' enabled", realm.getName());
                return;
              }

              PasswordPolicy passwordPolicy = realm.getPasswordPolicy();
              if (passwordPolicy == null
                  || !passwordPolicy.getPolicies().contains("disable-users-password-policy")) {
                LOG.debugf(
                    "realm='%s' does not have 'Disable Users' password policy set",
                    realm.getName());
                return;
              }

              int gracePeriodDays = passwordPolicy.getPolicyConfig("disable-users-password-policy");

              long gracePeriodMillis = gracePeriodDays * DAYS_TO_MILLIS;

              LOG.infof(
                  "checking realm='%s' for expired passwords or inactive accounts exceeding %d day(s)",
                  realm.getName(), gracePeriodDays);

              Predicate<UserModel> expiredPassword =
                  user -> {
                    CredentialModel credential =
                        passwordCredentialProvider.getPassword(realm, user);
                    if (credential != null
                        && ((currentTimeMillis - credential.getCreatedDate())
                            > gracePeriodMillis)) {
                      LOG.warnf(
                          "disabled realm='%s' user='%s' userId='%s' for expired password",
                          realm.getName(), user.getUsername(), user.getId());
                      return true;
                    }
                    return false;
                  };

              Predicate<UserModel> inactiveAccount =
                  user -> {
                    String lastLogin = user.getFirstAttribute(ATTRIBUTE_NAME);
                    if (NumberUtils.isNumber(lastLogin)
                        && ((currentTimeMillis - NumberUtils.toLong(lastLogin))
                            > gracePeriodMillis)) {
                      LOG.warnf(
                          "disabled realm='%s' user='%s' userId='%s' for inactive account",
                          realm.getName(), user.getUsername(), user.getId());
                      return true;
                    }
                    return false;
                  };

              Consumer<UserModel> disableUser =
                  user -> {
                    user.setEnabled(false);
                    session.userCache().evict(realm, user);
                  };

              session
                  .userLocalStorage()
                  .getUsersStream(realm)
                  .filter(UserModel::isEnabled)
                  .filter(expiredPassword.or(inactiveAccount))
                  .forEach(disableUser);
            });
  }
}
