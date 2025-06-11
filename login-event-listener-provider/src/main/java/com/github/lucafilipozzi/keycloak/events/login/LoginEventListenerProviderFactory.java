// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.events.login;

import static com.github.lucafilipozzi.keycloak.events.login.LoginEventListenerProvider.LAST_LOGIN_ATTRIBUTE_NAME;

import com.google.auto.service.AutoService;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.primitives.Longs;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.jbosslog.JBossLog;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.keycloak.storage.UserStorageUtil;
import org.keycloak.timer.TimerProvider;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class LoginEventListenerProviderFactory implements EventListenerProviderFactory {
  public static final String PROVIDER_ID = "login-event-listener";

  private static final String TASK_INTERVAL = "P1D";

  private static final String WARNING_INTERVALS = "-P8D, -P4D, -P2D";

  private static final String LAST_WARNING_ATTRIBUTE_NAME = "last-warning";

  private static final String DAYS_UNTIL_PASSWORD_EXPIRY_ATTRIBUTE_NAME = "days-until-password-expiry";

  private long taskInterval;

  private List<Long> warningIntervals;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LoginEventListenerProvider(session, Logger.getLogger("org.keycloak.events"));
  }

  @Override
  public void init(Config.Scope config) {
    taskInterval = Duration.parse(config.get("taskInterval", TASK_INTERVAL)).toMillis();
    warningIntervals = Stream.of(config.get("warningIntervals", WARNING_INTERVALS).split(",")).map(String::trim).map(Duration::parse).map(Duration::toMillis).toList();
  }

  @Override
  public void postInit(KeycloakSessionFactory sessionFactory) {
    sessionFactory.register(
        event -> {
          if (event instanceof PostMigrationEvent) {
            LOG.debug("registering warn-or-disable-users-task");
            try (KeycloakSession session = sessionFactory.create()) {
              TimerProvider timer = session.getProvider(TimerProvider.class);
              if (timer != null) {
                ClusterAwareScheduledTaskRunner clusterAwareScheduledTaskRunner = new ClusterAwareScheduledTaskRunner(sessionFactory, this::warnOrDisableUsersTask, taskInterval);
                timer.schedule(clusterAwareScheduledTaskRunner, taskInterval, "warn-or-disable-users-task");
              }
            }
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

  private void warnOrDisableUsersTask(KeycloakSession session) {
    long currentTime = Time.currentTimeMillis();

    PasswordCredentialProvider passwordCredentialProvider = (PasswordCredentialProvider) session.getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);

    EmailTemplateProvider emailTemplateProvider = session.getProvider(EmailTemplateProvider.class);

    Predicate<RealmModel> eventListenerEnabled = realm ->
        realm.getEventsListenersStream().anyMatch(eventListenerId -> eventListenerId.equals(PROVIDER_ID));

    Predicate<RealmModel> passwordPolicyEnabled = realm -> {
      PasswordPolicy passwordPolicy = realm.getPasswordPolicy();
      return Objects.nonNull(passwordPolicy)
          && passwordPolicy.getPolicies().contains("disable-users-password-policy")
          && passwordPolicy.getPolicies().contains(PasswordPolicy.FORCE_EXPIRED_ID)
          && passwordPolicy.getDaysToExpirePassword() >= 0;
    };

    session
        .realms()
        .getRealmsStream()
        .filter(eventListenerEnabled)
        .filter(passwordPolicyEnabled)
        .forEach(realm -> {
          LOG.infof("in realm '%s', warning or disabling users", realm.getName());

          UserCache userCache = UserStorageUtil.userCache(session);

          long maxLastLoginAge = Duration.ofDays(((Number)realm.getPasswordPolicy().getPolicyConfig("disable-users-password-policy")).longValue()).toMillis();

          long maxPasswordAge = Duration.ofDays(realm.getPasswordPolicy().getDaysToExpirePassword()).toMillis();

          Consumer<UserModel> warnOrDisableUser = user -> {
            long lastLoginTime = Optional.ofNullable(user.getFirstAttribute(LAST_LOGIN_ATTRIBUTE_NAME)).filter(Objects::nonNull).map(Longs::tryParse).orElse(0L);
            if (lastLoginTime > 0L && (currentTime - lastLoginTime) > maxLastLoginAge) {
              LOG.infof("in realm '%s', user '%s' disabled due to inactivity", realm.getName(), user.getUsername());
              user.setEnabled(false);
              user.removeAttribute(LAST_WARNING_ATTRIBUTE_NAME);
              user.removeAttribute(DAYS_UNTIL_PASSWORD_EXPIRY_ATTRIBUTE_NAME);
              userCache.evict(realm, user);
              return;
            }

            CredentialModel credential = passwordCredentialProvider.getPassword(realm, user);
            if (Objects.isNull(credential)) {
              LOG.debugf("in realm '%s', user '%s' has no password", realm.getName(), user.getUsername());
              user.removeAttribute(LAST_WARNING_ATTRIBUTE_NAME);
              user.removeAttribute(DAYS_UNTIL_PASSWORD_EXPIRY_ATTRIBUTE_NAME);
              userCache.evict(realm, user);
              return;
            }

            long credentialTime = credential.getCreatedDate();
            if ((currentTime - credentialTime) > maxPasswordAge) {
              LOG.infof("in realm '%s', user '%s' disabled due to expired password", realm.getName(), user.getUsername());
              user.setEnabled(false);
              user.removeAttribute(LAST_WARNING_ATTRIBUTE_NAME);
              user.removeAttribute(DAYS_UNTIL_PASSWORD_EXPIRY_ATTRIBUTE_NAME);
              userCache.evict(realm, user);
              return;
            }

            long passwordExpiringDays = Duration.ofMillis(credentialTime + maxPasswordAge - currentTime).toDays();
            long lastWarningTime = Optional.ofNullable(user.getFirstAttribute(LAST_WARNING_ATTRIBUTE_NAME)).filter(Objects::nonNull).map(Longs::tryParse).orElse(0L);
            long nextWarningTime = Optional.ofNullable(
                warningIntervals.stream().map(warningInterval -> warningInterval + maxPasswordAge + credentialTime).collect(Collectors.toCollection(TreeSet::new)).floor(currentTime)
            ).orElse(0L);
            if (lastWarningTime < nextWarningTime) {
              try {
                Map<String, Object> attributes = Maps.newHashMap(ImmutableMap.of("realm", realm, "user", user, "passwordExpiringDays", Long.toString(passwordExpiringDays)));
                emailTemplateProvider.setRealm(realm).setUser(user).send("passwordExpiringSubject", "password-expiring.ftl", attributes);
                user.setSingleAttribute(LAST_WARNING_ATTRIBUTE_NAME, Long.toString(currentTime));
                LOG.infof("in realm '%s', user '%s' warned that password expires in %d days", realm.getName(), user.getUsername(), passwordExpiringDays);
              } catch (EmailException e) {
                LOG.errorf("in realm '%s', user '%s' not warned that password expires in %d days", realm.getName(), user.getUsername(), passwordExpiringDays, e);
              }
            }

            user.setSingleAttribute(DAYS_UNTIL_PASSWORD_EXPIRY_ATTRIBUTE_NAME, Long.toString(Long.max(passwordExpiringDays, 0L)));
            userCache.evict(realm, user);
          };

          session.getContext().setRealm(realm);
          session.users().searchForUserStream(realm, Collections.emptyMap()).filter(UserModel::isEnabled).forEach(warnOrDisableUser);
          session.getContext().setRealm(null);
        });
  }
}
