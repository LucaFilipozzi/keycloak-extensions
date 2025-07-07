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
import java.util.List;
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
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.ClientRoleMappingsResource;
import org.keycloak.services.resources.admin.RealmAdminResource;
import org.keycloak.services.resources.admin.RoleMapperResource;
import org.keycloak.services.resources.admin.UserResource;
import org.keycloak.services.resources.admin.UsersResource;

@Provider
@Priority(Priorities.AUTHORIZATION)
@JBossLog
public class AdminResourcesRequestFilter implements ContainerRequestFilter {
  // users having this realm-management role assigned can only manage the credentials of other users
  private final static String MANAGE_CREDENTIALS_ONLY = "agency-manage-passwords";

  // users having this realm-management role assigned can only manage the profiles (and credentials) of other users
  private final static String MANAGE_PROFILE_ONLY = "manage-users"; // FIXME use: "agency-manage-users"

  // key is roleName, resourceClassName, resourceMethodName; value is boolean where false means deny
  private final MultiKeyMap<String, Boolean> permissions;

  // be efficient ... in filter(), below, only handle roles that have been added to the permission map
  private final Set<String> applicableRoleNames;

  @Context
  private KeycloakSession session;

  @Context
  private ResourceInfo resourceInfo;

  @Context
  private UriInfo uriInfo;

  public AdminResourcesRequestFilter() {
    // note to future self - we're using getDeclaredMethod() because:
    // (1) we want the filter() method to return quickly; it already has resourceInfo populated
    //     with resourceClass and resourceMethod, so let's use those directly rather than trying
    //     to parse uriInfo path ourselves or using an external dependency like casbin
    // (2) our IDE (IntelliJ IDEA) provides excellent support for populating the method name and
    //     method parameters for getDeclaredMethod, leaving no opportunity for typos
    //
    // but the use of getDeclaredMethod() makes this filter very sensitive to refactoring of the
    // following keycloak classes:
    //   * org.keycloak.services.resources.admin.ClientRoleMappingsResource
    //   * org.keycloak.services.resources.admin.RealmAdminResource
    //   * org.keycloak.services.resources.admin.RoleMapperResource
    //   * org.keycloak.services.resources.admin.UserResource
    //   * org.keycloak.services.resources.admin.UsersResource
    //
    // so let's catch any NoSuchMethodExceptions thrown during construction and throw an exception
    // that will prevent keycloak from starting ... this should get caught during upgrade testing
    //
    // remember, we prefer compile-time errors over startup-time errors over run-time errors

    try {

      permissions = new MultiKeyMap<>();

      // users
      Method getUsers = UsersResource.class.getDeclaredMethod("getUsers", String.class, String.class, String.class, String.class, String.class,
          Boolean.class, String.class, String.class, Integer.class, Integer.class, Boolean.class, Boolean.class, Boolean.class, String.class);
      Method getUser = UserResource.class.getDeclaredMethod("getUser", boolean.class);
      Method addUser = UsersResource.class.getDeclaredMethod("createUser", UserRepresentation.class);
      Method delUser = UserResource.class.getDeclaredMethod("deleteUser");
      Method modUser = UserResource.class.getDeclaredMethod("updateUser", UserRepresentation.class);
      denyAccess(ImmutableSet.of(MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(addUser, delUser, modUser));

      // credentials
      Method getCredentials = UserResource.class.getDeclaredMethod("credentials");
      Method addCredential = UserResource.class.getDeclaredMethod("resetPassword", CredentialRepresentation.class);
      Method delCredential = UserResource.class.getDeclaredMethod("removeCredential", String.class);

      // role mappings
      Method getRoleMappings = RoleMapperResource.class.getDeclaredMethod("getRoleMappings");
      Method addRealmRoleMappings = RoleMapperResource.class.getDeclaredMethod("addRealmRoleMappings", List.class);
      Method delRealmRoleMappings = RoleMapperResource.class.getDeclaredMethod("deleteRealmRoleMappings", List.class);
      Method addClientRoleMapping = ClientRoleMappingsResource.class.getDeclaredMethod("addClientRoleMapping", List.class);
      Method delClientRoleMapping = ClientRoleMappingsResource.class.getDeclaredMethod("deleteClientRoleMapping", List.class);
      denyAccess(ImmutableSet.of(MANAGE_PROFILE_ONLY, MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(getRoleMappings, addRealmRoleMappings, delRealmRoleMappings, addClientRoleMapping, delClientRoleMapping));

      // group memberships
      Method getGroupMemberships = UserResource.class.getDeclaredMethod("groupMembership", String.class, Integer.class, Integer.class, boolean.class);
      Method addGroupMembership = UserResource.class.getDeclaredMethod("joinGroup", String.class);
      Method delGroupMembership = UserResource.class.getDeclaredMethod("removeMembership", String.class);
      denyAccess(ImmutableSet.of(MANAGE_PROFILE_ONLY, MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(getGroupMemberships, addGroupMembership, delGroupMembership));

      // consents
      Method getConsents = UserResource.class.getDeclaredMethod("getConsents");
      Method delConsent = UserResource.class.getDeclaredMethod("revokeConsent", String.class);
      denyAccess(ImmutableSet.of(MANAGE_PROFILE_ONLY, MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(getConsents, delConsent));

      // federated identities
      Method getFederatedIdentities = UserResource.class.getDeclaredMethod("getFederatedIdentities", UserModel.class);
      Method getFederatedIdentity = UserResource.class.getDeclaredMethod("getFederatedIdentity");
      Method addFederatedIdentity = UserResource.class.getDeclaredMethod("addFederatedIdentity", String.class, FederatedIdentityRepresentation.class);
      Method delFederatedIdentity = UserResource.class.getDeclaredMethod("removeFederatedIdentity", String.class);
      denyAccess(ImmutableSet.of(MANAGE_PROFILE_ONLY, MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(getFederatedIdentities, getFederatedIdentity, addFederatedIdentity, delFederatedIdentity));

      // sessions
      Method getSessions = UserResource.class.getDeclaredMethod("getSessions");
      Method delSessions = UserResource.class.getDeclaredMethod("logout");
      Method delSession = RealmAdminResource.class.getDeclaredMethod("deleteSession", String.class, boolean.class);
      denyAccess(ImmutableSet.of(MANAGE_PROFILE_ONLY, MANAGE_CREDENTIALS_ONLY),
          ImmutableSet.of(getSessions, delSessions, delSession));

      applicableRoleNames = permissions.keySet().stream().map(multiKey -> multiKey.getKey(0)).collect(Collectors.toSet());

    } catch (NoSuchMethodException e) {

      throw new ComponentValidationException("AdminResourceRequestFilter could not be initialized");

    }
  }

  @Override
  public void filter(ContainerRequestContext requestContext) {
    if (!uriInfo.getPath().startsWith("/admin/realms/")) {
      return;
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

    // using injected resourceInfo to get the resourceClassName and resourceMethodName efficiently
    String resourceClassName = resourceInfo.getResourceClass().getName();
    String resourceMethodName = resourceInfo.getResourceMethod().getName();

    boolean permitted = user
        .getClientRoleMappingsStream(realmManagementClient)
        .map(RoleModel::getName)
        .filter(applicableRoleNames::contains) // note that allMatch() of an empty stream is true, which is desired behaviour (default allow)
        .allMatch(roleName -> Optional.ofNullable(permissions.get(roleName, resourceClassName, resourceMethodName)).orElse(true));

    if (permitted) {
      // TODO change to debugf
      LOG.infof("access granted: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          resourceClassName, resourceMethodName, realm.getName(), user.getUsername());
    } else {
      LOG.infof("access denied: resourceClassName=%s resourceMethodName=%s realm=%s user=%s",
          resourceClassName, resourceMethodName, realm.getName(), user.getUsername());
      requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
  }

  private void denyAccess(Set<String> roleNames, Set<Method> resourceMethods) {
    Sets.cartesianProduct(roleNames, resourceMethods).forEach(combination -> {
      String roleName = (String) combination.get(0);
      Method resourceMethod = (Method) combination.get(1);
      Class<?> resourceClass = resourceMethod.getDeclaringClass();
      // add MultiKey <roleName, resourceClassName, resourceMethodName> with value set to false for
      // operations to be DENIED to users having the specified roleName assigned; unless explicitly
      // added, operations are DEFAULT ALLOWED: see Optional.ofNullable().orElse(true) in filter()
      permissions.put(roleName, resourceClass.getName(), resourceMethod.getName(), false);
      // note to future self - using resourceMethod.getDeclaringClass().getName() and resourceMethod.getName()
      // for obtaining the respective names to add to the permissions map, thereby leaving no opportunity for typos
    });
  }
}
