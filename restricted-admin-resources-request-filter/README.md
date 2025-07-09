# restricted-admin-resources-request-filter

## description

Enabling Admin Permissions in a realm introduces five authorization
scopes for Users: `impersonation`, `manage`, `map-roles`, `view`, and
`manage-group-permissions`.

Unfortunately, the `manage` authorization scope for Users is insufficiently
fine-grained and allows an administrator to manage users' attributes _and_
their credentials. Enabling Admin Permissions only splits out management of
role assignments and management of group memberships. It would be useful to
also split out management of credentials so that an administrator could be
restricted to managing credentials without granting the ability to create
and delete users, or modifying their attributes (firstName, etc.).

Unfortunately, it is not possible to introduce additional authorization
scopes as the classes that would need overriding are not implemented using
Java service provider interfaces (SPIs). This leaves two options:
   * option 1 - implement an alternate admin UI, with new Resources
   * option 2 - apply access controls in the current ADMIN_V2 UI and
     filter calls to the existing Resources (i.e.: Users, User, etc.)

This module implements option 2 as follows:
   - via a script in a `restricted` admin theme that hides and/or
     disables DOM elements in Keycloak's ADMIN_V2 user interface
   - via a `RestrictedAdminResourcesRequestFilter` class that denies
     access to methods in various Resources (e.g.: `UsersResource`,
     `UserResource`, `RoleMapperResource`, `ClientRoleMappingsResource`)
     that correspond to the hidden and/or disabled elements

Specifically, the filter aborts requests if the resolved resourceClass
and resourceMethod exist in a permission map for the restricted roles. If
not found, then the filter allows the request to proceed. In other words,
the filter's behaviour is grant-unless-explicitly-denied.

The new roles are `realm-management.manage-profiles`
and `realm-management.manage-passwords`. They differ
from `realm-management.manage-users` as follows:

| capability                | manage-users | manage-profiles | manage-credentials |
|---------------------------|:------------:|:---------------:|:------------------:|
| query users               |     yes      |       yes       |        yes         |
| view user                 |     yes      |       yes       |        yes         |
| manage credentials        |     yes      |       yes       |        yes         |
| create/delete user        |     yes      |       yes       |         no         |
| enable/disable user       |     yes      |       yes       |         no         |
| manage attributes         |     yes      |       yes       |         no         |
| manage consents           |     yes      |       no        |         no         |
| manage id. provider links |     yes      |       no        |         no         |
| manage sessions           |     yes      |       no        |         no         |
| manage roles assignments  |     yes      |       no        |         no         |
| manage group memberships† |     yes      |       no        |         no         |

† Please see note 1.

## usage

1. copy the JAR to the providers directory and rebuild the optimized jar
2. set admin theme to `restricted`
3. modify `realm-management.manage-users`:
    - remove associated role `realm-management.query-groups`
4. create two new roles in client `realm-management`:
   - `manage-credentials` with
      - description: manage credentials only
      - associated roles:
         - `realm-management.query-users`
         - `realm-management.manage-users` (please see note 2)
         - `realm-management.view-users`
   - `manage-profiles` with
      - description: manage attributes and credentials
      - associated roles:
         - `realm-management.query-users`
         - `realm-management.manage-users` (please see note 2)
         - `realm-management.view-users`
5. assign the new roles to administrators

## notes

1. By default, in the `realm-management` client, the `manage-users` role
   is composited with the `query-groups` role. In order to remove manage
   groups capability from the `manage-profiles` and `manage-credentials`
   roles, we remove the `query-groups` role in step 3, above.
2. Even though the new roles are composited with the `manage-users` role,
   the theme's `hide-or-disable-elements.js` script and the 
   `RestrictedAdminResourcesRequestFilter` class achieve the capability
   restrictions enumerated in the table above.
3. It is not required to enable Admin Permissions to use this module.

---

© 2025 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
