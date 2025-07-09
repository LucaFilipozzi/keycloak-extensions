// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.filter;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.collections4.map.MultiKeyMap;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.ClientRoleMappingsResource;
import org.keycloak.services.resources.admin.RealmAdminResource;
import org.keycloak.services.resources.admin.RoleMapperResource;
import org.keycloak.services.resources.admin.UserResource;
import org.keycloak.services.resources.admin.UsersResource;

@Provider
@Priority(Priorities.AUTHORIZATION)
@JBossLog
public class RestrictedAdminResourcesRequestFilter implements ContainerRequestFilter {
  // users having this realm-management role assigned can only manage the profiles and credentials of other users
  private final static String MANAGE_PROFILES = "manage-profiles";

  // users having this realm-management role assigned can only manage the credentials of other users
  private final static String MANAGE_CREDENTIALS = "manage-credentials";

  // key is roleName, resourceClassName, resourceMethodName; value is boolean where false means deny
  private final MultiKeyMap<String, Boolean> permissions;

  // be efficient ... in filter(), below, only handle roles that have been added to the permission map
  private final Set<String> actionableRoleNames;

  @Context
  private KeycloakSession session;

  @Context
  private ResourceInfo resourceInfo;

  @Context
  private UriInfo uriInfo;

  public RestrictedAdminResourcesRequestFilter() {
    try {

      permissions = new MultiKeyMap<>();

      // users
      Method getUsers = findMethod(UsersResource.class,"getUsers");
      Method getUser = findMethod(UserResource.class,"getUser");
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

      actionableRoleNames = permissions.keySet().stream().map(multiKey -> multiKey.getKey(0)).collect(Collectors.toSet());

    } catch (NoSuchMethodException e) {

      // since reflection is sensitive to future refactoring, let's catch any
      // NoSuchMethodExceptions thrown during construction and throw an exception
      // that will prevent keycloak from starting (ComponentValidationException)
      throw new ComponentValidationException("AdminResourceRequestFilter could not be initialized");

    }
  }

  @Override
  public void filter(ContainerRequestContext requestContext) {
    if (!uriInfo.getPath().startsWith("/admin/realms/")) {
      return; // path-based guard
    }

    UserModel user = session.getContext().getUser();
    if (user == null) { // should never happen given the path-based guard above
      LOG.error("user is null");
      return;
    }

    RealmModel realm = session.getContext().getRealm();
    if (realm == null) { // should never happen given the path-based guard above
      LOG.error("realm is null");
      return;
    }

    ClientModel realmManagementClient = session.clients().getClientByClientId(realm, "realm-management");
    if (realmManagementClient == null) { // should never happen given the path-based guard above
      LOG.error("realm-management client is null");
      return;
    }

    // using resourceClassName and resourceMethodName from injected resourceInfo
    // is more efficient than parsing uriInfo path ourselves and much simpler than
    // adding an external authorization dependency such as https://casbin.org/
    String resourceClassName = resourceInfo.getResourceClass().getName();
    String resourceMethodName = resourceInfo.getResourceMethod().getName();

    boolean permitted = user
        .getClientRoleMappingsStream(realmManagementClient)
        .map(RoleModel::getName)
        .filter(actionableRoleNames::contains) // note that allMatch() of an empty stream is true, which is desired behaviour (default allow)
        .allMatch(roleName -> Optional.ofNullable(permissions.get(roleName, resourceClassName, resourceMethodName)).orElse(true));

    if (permitted) {
      LOG.tracef("access granted: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          resourceClassName, resourceMethodName, realm.getName(), user.getUsername());
    } else {
      LOG.tracef("access denied: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          resourceClassName, resourceMethodName, realm.getName(), user.getUsername());
      requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
  }

  private void denyAccess(Set<String> roleNames, Set<Method> resourceMethods) {
    Sets.cartesianProduct(roleNames, resourceMethods).forEach(combination -> {
      String roleName = (String) combination.get(0);
      Method resourceMethod = (Method) combination.get(1);
      Class<?> resourceClass = resourceMethod.getDeclaringClass();
      permissions.put(roleName, resourceClass.getName(), resourceMethod.getName(), false);
    });
  }

  private Method findMethod(Class<?> clazz, String methodName) throws NoSuchMethodException {
    return Arrays.stream(clazz.getDeclaredMethods())
        .filter(method -> method.getName().equals(methodName))
        .findFirst()
        .orElseThrow(NoSuchMethodException::new);
  }
}
