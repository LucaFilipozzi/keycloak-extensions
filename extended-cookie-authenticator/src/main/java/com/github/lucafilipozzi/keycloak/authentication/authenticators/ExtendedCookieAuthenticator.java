// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.authentication.authenticators;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

@JBossLog
public class ExtendedCookieAuthenticator extends CookieAuthenticator implements Authenticator {
  private static final String IMPERSONATOR_ID = ImpersonationSessionNote.IMPERSONATOR_ID.toString();

  private static final String IMPERSONATOR_ROLES = "IMPERSONATOR_ROLES";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    RealmModel realm = context.getRealm();
    KeycloakSession session = context.getSession();
    AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
    if (authResult == null) {
      LOG.debug("authentication by cookie failed");
      context.attempted();
      return;
    }

    LOG.debug("authentication by cookie succeeded");
    UserSessionModel userSession = authResult.getSession();
    if (!userSession.getNotes().containsKey(IMPERSONATOR_ID)) {
      LOG.debug("impersonation not active");
      super.authenticate(context);
      return;
    }

    String impersonatorId = userSession.getNotes().get(IMPERSONATOR_ID);
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
      userSession.setNote(IMPERSONATOR_ROLES, roleIntersection.stream()
          .map(RoleModel::getName).collect(Collectors.joining(",")));
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
    return Stream.concat(Stream.of(role), role.getCompositesStream().flatMap(ExtendedCookieAuthenticator::getDeepRoleCompositesStream));
  }
}
