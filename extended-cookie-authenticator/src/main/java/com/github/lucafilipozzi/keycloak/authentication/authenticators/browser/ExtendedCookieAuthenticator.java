// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators.browser;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

public class ExtendedCookieAuthenticator extends CookieAuthenticator implements Authenticator {
  private static final Logger LOG = Logger.getLogger(ExtendedCookieAuthenticator.class);

  public static final String FORCE_REAUTHENTICATION = "forceReauthentication";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    RealmModel realm = context.getRealm();
    KeycloakSession session = context.getSession();
    AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
    if (authResult == null) {
      context.attempted();
      return;
    }

    UserSessionModel userSession = authResult.getSession();
    if (!userSession.getNotes().containsKey(ImpersonationSessionNote.IMPERSONATOR_ID.toString())) {
      LOG.debug("impersonation not active");
      if (Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get(FORCE_REAUTHENTICATION))) {
        LOG.debug("force reauthentication enabled");
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        AcrStore acrStore = new AcrStore(authSession);
        acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
        authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
        context.setForwardedInfoMessage(Messages.REAUTHENTICATE);
        context.attempted();
        return;
      }
      super.authenticate(context);
      return;
    }

    String impersonatorId = userSession.getNotes().get(ImpersonationSessionNote.IMPERSONATOR_ID.toString());
    UserModel impersonator = session.users().getUserById(realm, impersonatorId);
    RoleModel requiredRole = realm.getClientByClientId("realm-management").getRole("impersonation");
    if (impersonator == null || requiredRole == null) {
      LOG.debug("internal error");
      Response response = context.form()
          .setError("Server Misconfiguration")
          .createErrorPage(Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
      return;
    }

    ClientModel client = context.getAuthenticationSession().getClient();
    Set<RoleModel> clientRoles = client.getRolesStream()
        .filter(RoleModel::isComposite)
        .filter(x -> getDeepRoleCompositesStream(x).anyMatch(y -> y.equals(requiredRole)))
        .collect(Collectors.toSet());
    Set<RoleModel> impersonatorRoles = RoleUtils.getDeepUserRoleMappings(impersonator);
    Set<RoleModel> roleIntersection = Sets.intersection(clientRoles, impersonatorRoles);
    if (!roleIntersection.isEmpty()) {
      LOG.debug("access granted to impersonator");
      String roles = roleIntersection.stream().map(RoleModel::getName).collect(Collectors.joining(","));
      userSession.setNote("IMPERSONATOR_ROLES", roles);
      super.authenticate(context);
      return;
    }

    LOG.debug("access denied to impersonator");
    Response response = context.form()
        .setError("Impersonator Access Denied")
        .createErrorPage(Status.FORBIDDEN);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
  }

  private static Stream<RoleModel> getDeepRoleCompositesStream(final RoleModel role) { // helper function
    return Stream.concat(Stream.of(role), role.getCompositesStream().flatMap(x -> getDeepRoleCompositesStream(x)));
  }
}
