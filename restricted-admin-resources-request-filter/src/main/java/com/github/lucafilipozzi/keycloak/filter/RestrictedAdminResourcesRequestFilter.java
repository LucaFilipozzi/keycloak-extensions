// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.filter;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.account.AccountRestService;
import org.keycloak.services.resources.account.SessionResource;
import org.keycloak.services.resources.admin.ClientRoleMappingsResource;
import org.keycloak.services.resources.admin.RealmAdminResource;
import org.keycloak.services.resources.admin.RoleMapperResource;
import org.keycloak.services.resources.admin.UserResource;
import org.keycloak.services.resources.admin.UsersResource;

@Provider
@Priority(Priorities.AUTHORIZATION)
@JBossLog
public class RestrictedAdminResourcesRequestFilter implements ContainerRequestFilter {

  @Data
  @RequiredArgsConstructor(staticName = "of")
  private static class ControlledResource {
    @NonNull
    private String className;
    @NonNull
    private String methodName;
  }

  // theme name (see src/main/resources/META-INF/keycloak-themes.conf)
  private static final String THEME = "restricted";

  // users having this new `realm-management` client role assigned can only manage the profiles and credentials of other users
  private static final String MANAGE_PROFILES = "manage-profiles";

  // users having this new `realm-management` client role assigned can only manage the credentials of other users
  private static final String MANAGE_CREDENTIALS = "manage-credentials";

  // users having this existing `account` client role assigned will be restricted to managing their own password only
  private static final String MANAGE_ACCOUNT = "manage-account";

  // be efficient ... in filter(), below, only handle roles that can be added to the permission map
  private static final Set<String> controllingRoleNames = ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS, MANAGE_ACCOUNT);

  // rowKey is controlledResource, columnKey is controllingRoleName; value is boolean where false means deny
  private final Table<ControlledResource, String, Boolean> permissionsTable = HashBasedTable.create();

  @Context
  private KeycloakSession session;

  @Context
  private ResourceInfo resourceInfo;

  public RestrictedAdminResourcesRequestFilter() {
    try {
      denyAccessToAccountConsoleResources();
      denyAccessToSecurityAdminConsoleResources();
    } catch (NoSuchMethodException e) {
      // since reflection is sensitive to future refactoring, let's catch any
      // NoSuchMethodExceptions thrown during construction and throw an exception
      // that will prevent keycloak from starting (ComponentValidationException)
      throw new ComponentValidationException(
          RestrictedAdminResourcesRequestFilter.class.getSimpleName() + " could not be initialized");
    }
  }

  @Override
  public void filter(ContainerRequestContext requestContext) {
    if (resourceInfo == null) {
      return; // return early if not filtering a request for a resource
    }

    // Using resourceClass and resourceMethod from injected resourceInfo is
    // more efficient than parsing uriInfo path ourselves and much simpler than
    // adding an authorization dependency such as https://casbin.org/.
    ControlledResource controlledResource = ControlledResource.of(
        resourceInfo.getResourceClass().getName(),
        resourceInfo.getResourceMethod().getName());
    if (!permissionsTable.containsRow(controlledResource)) {
      return; // return early if not filtering a request for a _controlled_ resource
    }

    KeycloakContext context = session.getContext();
    if (context == null) {
      return; // should never happen
    }

    UserModel user = context.getUser();
    if (user == null) {
      return; // should never happen
    }

    RealmModel realm = context.getRealm();
    if (realm == null) {
      return; // should never happen
    }

    // consoleClient is the React application (i.e., account-console or security-admin-console) that,
    // on behalf of the logged-in user, is attempting to access the resource that we are controlling.
    ClientModel consoleClient = context.getClient();
    if (consoleClient == null) {
      return; // should never happen
    }

    // roleClient contains the roles through whose assignment the logged-in user is granted (or
    // denied if the console's theme is THEME) access to the resource that we are controlling.
    // Here, we map consoleClient to roleClient but only if the console's theme is THEME as that
    // is indicative of the administrator's desire for this filter to be applied to resources.
    ClientModel roleClient = session.clients()
        .getClientByClientId( // returns null if switch-resolved clientId is null
            realm,
            switch (consoleClient.getClientId()) {
              case "account-console" -> realm.getAccountTheme().equals(THEME) ? "account" : null;
              case "security-admin-console" -> realm.getAdminTheme().equals(THEME) ? "realm-management" : null;
              default -> null;
            }
        );
    if (roleClient == null) {
      return; // could happen if not a console client or console's theme isn't THEME
    }

    boolean permitted = session.roles()
        .getClientRolesStream(roleClient)
        // filter may result in an empty stream
        .filter(user::hasRole)
        .map(RoleModel::getName)
        // filter may result in an empty stream
        .filter(controllingRoleNames::contains)
        // allMatch of an empty stream returns true (default grant access)
        .allMatch(controllingRoleName -> Optional
            .ofNullable(permissionsTable.get(controlledResource, controllingRoleName))
            .orElse(true));

    if (permitted) {
      LOG.debugf("access granted: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          controlledResource.getClassName(), controlledResource.getMethodName(), realm.getName(), user.getUsername());
    } else {
      LOG.debugf("access denied: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          controlledResource.getClassName(), controlledResource.getMethodName(), realm.getName(), user.getUsername());
      requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
  }

  private void denyAccessToAccountConsoleResources() throws NoSuchMethodException{
    Method getAccount = findMethod(AccountRestService.class, "account");
    Method modAccount = findMethod(AccountRestService.class, "updateAccount");
    Method getApplications = findMethod(AccountRestService.class, "applications");
    Method getConsent = findMethod(AccountRestService.class, "getConsent");
    Method addConsent = findMethod(AccountRestService.class, "grantConsent");
    Method delConsent = findMethod(AccountRestService.class, "revokeConsent");
    Method modConsent = findMethod(AccountRestService.class, "updateConsent");
    Method getCredentials = findMethod(AccountRestService.class, "credentials");
    Method getDevices = findMethod(SessionResource.class, "devices");
    Method getGroupMemberships = findMethod(AccountRestService.class, "groupMemberships");
    Method getLinkedAccounts = findMethod(AccountRestService.class, "linkedAccounts");
    Method getOrganizations = findMethod(AccountRestService.class, "organizations");
    Method getResources = findMethod(AccountRestService.class, "resources");
    Method getSessions = findMethod(AccountRestService.class, "sessions");
    denyAccess(ImmutableSet.of(), // get rid of 'method not used' warnings
        ImmutableSet.of(getAccount, getCredentials));
    denyAccess(ImmutableSet.of(MANAGE_ACCOUNT),
        ImmutableSet.of(modAccount, getApplications, getConsent, addConsent, delConsent, modConsent,
            getDevices, getGroupMemberships, getLinkedAccounts, getOrganizations, getResources, getSessions));
  }

  private void denyAccessToSecurityAdminConsoleResources() throws NoSuchMethodException {
    // users
    Method getUsers = findMethod(UsersResource.class, "getUsers");
    Method getUser = findMethod(UserResource.class, "getUser");
    Method addUser = findMethod(UsersResource.class, "createUser");
    Method delUser = findMethod(UserResource.class, "deleteUser");
    Method modUser = findMethod(UserResource.class, "updateUser");
    denyAccess(ImmutableSet.of(), // get rid of 'method not used' warnings
        ImmutableSet.of(getUsers, getUser));
    denyAccess(ImmutableSet.of(MANAGE_CREDENTIALS),
        ImmutableSet.of(addUser, delUser, modUser));

    // credentials
    Method getCredentials = findMethod(UserResource.class, "credentials");
    Method addCredential = findMethod(UserResource.class, "resetPassword");
    Method delCredential = findMethod(UserResource.class, "removeCredential");
    Method modCredential = findMethod(UserResource.class, "setCredentialUserLabel");
    denyAccess(ImmutableSet.of(), // get rid of 'method not used' warnings
        ImmutableSet.of(getCredentials, addCredential, delCredential, modCredential));

    // role mappings
    Method getRoleMappings = findMethod(RoleMapperResource.class, "getRoleMappings");
    Method addRealmRoleMappings = findMethod(RoleMapperResource.class, "addRealmRoleMappings");
    Method delRealmRoleMappings = findMethod(RoleMapperResource.class, "deleteRealmRoleMappings");
    Method addClientRoleMappings = findMethod(ClientRoleMappingsResource.class, "addClientRoleMapping");
    Method delClientRoleMappings = findMethod(ClientRoleMappingsResource.class, "deleteClientRoleMapping");
    denyAccess(ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS),
        ImmutableSet.of(getRoleMappings, addRealmRoleMappings, delRealmRoleMappings, addClientRoleMappings, delClientRoleMappings));

    // group memberships
    Method getGroupMemberships = findMethod(UserResource.class, "groupMembership");
    Method addGroupMembership = findMethod(UserResource.class, "joinGroup");
    Method delGroupMembership = findMethod(UserResource.class, "removeMembership");
    denyAccess(ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS),
        ImmutableSet.of(getGroupMemberships, addGroupMembership, delGroupMembership));

    // consents
    Method getConsents = findMethod(UserResource.class, "getConsents");
    Method delConsent = findMethod(UserResource.class, "revokeConsent");
    denyAccess(ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS),
        ImmutableSet.of(getConsents, delConsent));

    // federated identities
    Method getFederatedIdentities = findMethod(UserResource.class, "getFederatedIdentities");
    Method getFederatedIdentity = findMethod(UserResource.class, "getFederatedIdentity");
    Method addFederatedIdentity = findMethod(UserResource.class, "addFederatedIdentity");
    Method delFederatedIdentity = findMethod(UserResource.class, "removeFederatedIdentity");
    denyAccess(ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS),
        ImmutableSet.of(getFederatedIdentities, getFederatedIdentity, addFederatedIdentity, delFederatedIdentity));

    // sessions
    Method getOnlineSessions = findMethod(UserResource.class, "getSessions");
    Method getOfflineSessions = findMethod(UserResource.class, "getOfflineSessions");
    Method delOnlineSessions = findMethod(UserResource.class, "logout");
    Method deleteOnlineOrOfflineSession = findMethod(RealmAdminResource.class, "deleteSession");
    denyAccess(ImmutableSet.of(MANAGE_PROFILES, MANAGE_CREDENTIALS),
        ImmutableSet.of(getOnlineSessions, getOfflineSessions, delOnlineSessions, deleteOnlineOrOfflineSession));
  }

  private void denyAccess(Set<String> controllingRoleNames, Set<Method> resourceMethods) {
    Sets.cartesianProduct(controllingRoleNames, resourceMethods).forEach(combination -> {
      String controllingRoleName = (String) combination.get(0);
      Method resourceMethod = (Method) combination.get(1);
      ControlledResource controlledResource = ControlledResource.of(
          resourceMethod.getDeclaringClass().getName(),
          resourceMethod.getName());
      permissionsTable.put(controlledResource, controllingRoleName, false);
    });
  }

  private Method findMethod(Class<?> clazz, String methodName) throws NoSuchMethodException {
    return Arrays.stream(clazz.getDeclaredMethods())
        .filter(method -> method.getName().equals(methodName))
        .findFirst()
        .orElseThrow(NoSuchMethodException::new);
  }
}
