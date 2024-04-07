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
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.timer.TimerProvider;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class LoginEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "login-event-listener";

  private static final long EXPIRED_PASSWORD_GRACE_PERIOD =
      60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  //
  private static final long INACTIVE_ACCOUNT_GRACE_PERIOD =
      60 * 24 * 60 * 60 * 1000L; // 60 days in milliseconds
  //
  private static final long DISABLE_USERS_TASK_INTERVAL =
      24 * 60 * 60 * 1000L; //  1 day  in milliseconds

  private long expiredPasswordGracePeriod;

  private long inactiveAccountGracePeriod;

  private long disableUsersTaskInterval;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LoginEventListenerProvider(session, Logger.getLogger("org.keycloak.events"));
  }

  @Override
  public void init(Config.Scope config) {
    expiredPasswordGracePeriod =
        config.getLong("expiredPasswordGradePeriod", EXPIRED_PASSWORD_GRACE_PERIOD);
    inactiveAccountGracePeriod =
        config.getLong("inactiveAccountGracePeriod", INACTIVE_ACCOUNT_GRACE_PERIOD);
    disableUsersTaskInterval =
        config.getLong("disableUsersTaskInterval", DISABLE_USERS_TASK_INTERVAL);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    factory.register(
        event -> {
          if (event instanceof PostMigrationEvent) {
            KeycloakSession session = factory.create();
            TimerProvider timer = session.getProvider(TimerProvider.class);
            timer.scheduleTask(this::disableUsers, disableUsersTaskInterval, "disable-users-task");
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
        .filter(
            realm ->
                realm
                    .getEventsListenersStream()
                    .anyMatch(eventListenerName -> eventListenerName.equals(PROVIDER_ID)))
        .forEach(
            realm -> {
              Predicate<UserModel> expiredPassword =
                  user -> {
                    CredentialModel credential =
                        passwordCredentialProvider.getPassword(realm, user);
                    if (credential != null
                        && ((currentTimeMillis - credential.getCreatedDate())
                            > expiredPasswordGracePeriod)) {
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
                            > inactiveAccountGracePeriod)) {
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

              LOG.debugf(
                  "checking realm='%s' for expired passwords or inactive accounts",
                  realm.getName());

              session
                  .userLocalStorage()
                  .getUsersStream(realm)
                  .filter(UserModel::isEnabled)
                  .filter(expiredPassword.or(inactiveAccount))
                  .forEach(disableUser);
            });
  }
}
