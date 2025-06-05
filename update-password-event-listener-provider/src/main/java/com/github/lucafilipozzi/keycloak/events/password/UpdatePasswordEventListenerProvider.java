// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.events.password;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

@JBossLog
@RequiredArgsConstructor
public class UpdatePasswordEventListenerProvider implements EventListenerProvider {
  private static final String PATTERN = "yyyy-MM-dd HH:mm:ss z";

  private static final String TIMEZONE = "America/Vancouver";

  @SuppressFBWarnings("EI_EXPOSE_REP2")
  private final KeycloakSession session;

  @Override
  public void onEvent(Event event) {
    if (EventType.UPDATE_CREDENTIAL.equals(event.getType()) && PasswordCredentialModel.TYPE.equals(event.getDetails().get(Details.CREDENTIAL_TYPE))) {
      RealmModel realm = session.realms().getRealm(event.getRealmId());
      UserModel user = session.users().getUserById(realm, event.getUserId());
      onEvent(realm, user);
    }
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    if (event.getResourceType() == ResourceType.USER
        && event.getOperationType() == OperationType.ACTION
        && event.getResourcePath().endsWith("/reset-password")) {
      RealmModel realm = session.realms().getRealm(event.getRealmId());
      UserModel user = session.users().getUserById(realm, event.getResourcePath().split("/")[1]);
      onEvent(realm, user);
    }
  }

  private void onEvent(RealmModel realm, UserModel sourceUser) {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(PATTERN);
    simpleDateFormat.setTimeZone(TimeZone.getTimeZone(TIMEZONE));

    PasswordCredentialProvider passwordCredentialProvider =
        (PasswordCredentialProvider)
            session.getProvider(
                CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);

    CredentialModel sourceCredential = passwordCredentialProvider.getPassword(realm, sourceUser);

    PasswordCredentialModel targetCredential =
        PasswordCredentialModel.createFromCredentialModel(sourceCredential);
    targetCredential.setId(null);
    targetCredential.setUserLabel("password synced from " +
      sourceUser.getUsername() + " on " +
      simpleDateFormat.format(Time.toDate(Time.currentTime())));

    sourceUser
        .getAttributeStream("password-sync")
        .forEach(
            targetUsername -> {
              UserModel targetUser = session.users().getUserByUsername(realm, targetUsername);
              if (targetUser == null) {
                LOG.debugf(
                    "password not synced from %s to %s (not found)",
                    sourceUser.getUsername(), targetUsername);
                return;
              }

              // update credential
              passwordCredentialProvider.createCredential(realm, targetUser, targetCredential);

              LOG.debugf("password synced from %s to %s", sourceUser.getUsername(), targetUsername);
            });
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
