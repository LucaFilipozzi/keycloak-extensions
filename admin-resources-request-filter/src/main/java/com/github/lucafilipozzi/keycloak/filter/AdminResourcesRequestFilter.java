// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.filter;

import com.google.common.collect.ImmutableList;
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
  private final static String AGENCY_MANAGE_PASSWORDS = "agency-manage-passwords";

  private final static String AGENCY_MANAGE_USERS = "agency-manage-users";

  private final MultiKeyMap<String, Boolean> permissions;

  private final Set<String> roles;

  @Context
  private KeycloakSession session;

  @Context
  private ResourceInfo resourceInfo;

  @Context
  private UriInfo uriInfo;

  public AdminResourcesRequestFilter() throws NoSuchMethodException {
    permissions = new MultiKeyMap<>();

    // users
    Method addUser = UsersResource.class.getDeclaredMethod("createUser", UserRepresentation.class);
    Method delUser = UserResource.class.getDeclaredMethod("deleteUser");
    Method modUser = UserResource.class.getDeclaredMethod("updateUser", UserRepresentation.class);
    denyAccess(ImmutableList.of(AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(addUser, delUser, modUser));
    // admins who have agency-manage-users can add, del, and mod users

    // credentials
    Method getCredentials = UserResource.class.getDeclaredMethod("credentials");
    Method addCredential = UserResource.class.getDeclaredMethod("resetPassword", CredentialRepresentation.class);
    Method delCredential = UserResource.class.getDeclaredMethod("removeCredential", String.class);
    // admins who have agency-manage-users and agency-manage-passwords roles can reset passwords

    // role mappings
    Method getRoleMappings = RoleMapperResource.class.getDeclaredMethod("getRoleMappings");
    Method addRealmRoleMappings = RoleMapperResource.class.getDeclaredMethod("addRealmRoleMappings", List.class);
    Method delRealmRoleMappings = RoleMapperResource.class.getDeclaredMethod("deleteRealmRoleMappings", List.class);
    Method addClientRoleMapping = ClientRoleMappingsResource.class.getDeclaredMethod("addClientRoleMapping", List.class);
    Method delClientRoleMapping = ClientRoleMappingsResource.class.getDeclaredMethod("deleteClientRoleMapping", List.class);
    denyAccess(ImmutableList.of(AGENCY_MANAGE_USERS, AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(getRoleMappings, addRealmRoleMappings, delRealmRoleMappings, addClientRoleMapping, delClientRoleMapping));

    // group memberships
    Method getGroupMemberships = UserResource.class.getDeclaredMethod("groupMembership", String.class, Integer.class, Integer.class, boolean.class);
    Method addGroupMembership = UserResource.class.getDeclaredMethod("joinGroup", String.class);
    Method delGroupMembership = UserResource.class.getDeclaredMethod("removeMembership", String.class);
    denyAccess("manage-users", ImmutableList.of(getGroupMemberships, addGroupMembership, delGroupMembership));
    denyAccess(ImmutableList.of(AGENCY_MANAGE_USERS, AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(getGroupMemberships, addGroupMembership, delGroupMembership));

    // consents
    Method getConsents = UserResource.class.getDeclaredMethod("getConsents");
    Method delConsent = UserResource.class.getDeclaredMethod("revokeConsent", String.class);
    denyAccess(ImmutableList.of(AGENCY_MANAGE_USERS, AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(getConsents, delConsent));

    // federated identities
    Method getFederatedIdentities = UserResource.class.getDeclaredMethod("getFederatedIdentities", UserModel.class);
    Method getFederatedIdentity = UserResource.class.getDeclaredMethod("getFederatedIdentity");
    Method addFederatedIdentity = UserResource.class.getDeclaredMethod("addFederatedIdentity", String.class, FederatedIdentityRepresentation.class);
    Method delFederatedIdentity = UserResource.class.getDeclaredMethod("removeFederatedIdentity", String.class);
    denyAccess(ImmutableList.of(AGENCY_MANAGE_USERS, AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(getFederatedIdentities, getFederatedIdentity, addFederatedIdentity, delFederatedIdentity));

    // sessions
    Method getSessions = UserResource.class.getDeclaredMethod("getSessions");
    Method delSessions = UserResource.class.getDeclaredMethod("logout");
    Method delSession = RealmAdminResource.class.getDeclaredMethod("deleteSession", String.class, boolean.class);
    denyAccess(ImmutableList.of(AGENCY_MANAGE_USERS, AGENCY_MANAGE_PASSWORDS),
        ImmutableList.of(getSessions, delSessions, delSession));

    roles = permissions.keySet().stream().map(multiKey -> multiKey.getKey(0)).collect(Collectors.toSet());
  }

  @Override
  public void filter(ContainerRequestContext requestContext) {
    if (!uriInfo.getPath().startsWith("/admin/realms/")) {
      return;
    }

    UserModel user = session.getContext().getUser();
    if (user == null) {
      LOG.error("user is null"); // should never happen
      return;
    }

    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      LOG.error("realm is null"); // should never happen
      return;
    }

    ClientModel client = session.clients().getClientByClientId(realm, "realm-management");
    if (client == null) {
      LOG.error("realm-management client is null"); // should never happen
      return;
    }

    String resourceClassName = resourceInfo.getResourceClass().getName();

    String resourceMethodName = resourceInfo.getResourceMethod().getName();

    boolean permitted = user
        .getClientRoleMappingsStream(client)
        .map(RoleModel::getName)
        .filter(roles::contains) // be efficient; note that allMatch() of an empty stream is true
        .allMatch(roleName -> Optional.ofNullable(permissions.get(roleName, resourceClassName, resourceMethodName)).orElse(true));

    LOG.infof("resourceClassName=%s resourceMethodName=%s permitted=%b", resourceClassName, resourceMethodName, permitted);

    if (!permitted) {
      requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
  }

  private void denyAccess(List<String> roleNames, List<Method> resourceMethods) {
    roleNames.forEach(roleName -> denyAccess(roleName, resourceMethods));
  }

  private void denyAccess(String roleName, List<Method> resourceMethods) {
    resourceMethods.forEach(resourceMethod -> denyAccess(roleName, resourceMethod));
  }

  private void denyAccess(String roleName, Method resourceMethod) {
    // add MultiKey <roleName, resourceClassName, resourceMethodName> with value set to false for
    // operations to be DENIED to users having the specified roleName assigned; unless explicitly
    // added, operations are DEFAULT ALLOWED: see Optional.ofNullable().orElse(true) in filter()
    permissions.put(roleName, resourceMethod.getDeclaringClass().getName(), resourceMethod.getName(), false);
  }
}
