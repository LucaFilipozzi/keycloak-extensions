# require-role-authenticator

## description

This authenticator takes inspiration from [Thomas Darimont][thomasd]'s
[auth-require-role-extension][authext] but extends upon the concept by allowing
the role requirement to be applied to the impersonator rather than the user.

Thus, this authenticator may be used similarly to Thomas' by requiring a user
to have the specified role in order for access to proceed.

But it may also be used to require that an impersonator have a role. When
applied on a client-basis, this allow for client-by-client impersonation
control.

This authenticator will add to user session notes the array of client roles
that match the required role and that the impersonator has, under the
IMPERSONATOR_ROLES key. If this authenticator is used more than once to
enforce a required role of an impersonator, only the latest one will
set the value on the user session note, overwriting previous value(s).

## deployment

After building with `mvn package`, copy
`target/require-role-authenticator-«version».jar` into
`${KEYCLOAK_HOME}/providers` and use `kc.sh build` to rebuild your keycloak
binary.

## configuration

This authenticator exposes two configuration parameters:

* __apply to impersonator__ - Specify whether to apply the role requirement to
                              the user (default; off) or to the impersonator
                              (on).

* __required role name__ - Specify the name of the role that a user is required
                           to have for successful authentication.  This can be
                           a realm or client role. Client roles have the form
                           'clientId.roleName' for a specific client.
                           Alternately, the expression '${clientId}.roleName'
                           may be used to specify a role of the current client. 

Note that if the required role name does not resolve to a role, then the
authentication will fail.

Note further that requiring a role of an impersonator must only be configured
in browser/cookie flows.

## example

### identity provider

In this example, Keycloak is an identity provider to clients.

1. Create two client roles:

    * _impersonator_ - Impersonators who have this client role will be
                       permitted to access the client as an impersonated user.
                       Composite this role with _realm-management.impersonation_,
                       and _realm-management.view-users_.

    * _accessor_ - Users who have this client role will be permitted to access the client.

2. Create a browser authentication flow as follows:

   | auth type   |                             | requirement   |               |               |               |
   | ------------| --------------------------- | ------------- | ------------- | ------------- | ------------- |
   | Cookie Auth |                             | ○ REQUIRED    | ● ALTERNATIVE | ○ DISABLED    | ○ CONDITIONAL |
   |             | Cookie                      | ● REQUIRED    | ○ ALTERNATIVE | ○ DISABLED    |               |
   |             | Require Role (impersonator) | ● REQUIRED    | ○ ALTERNATIVE | ○ DISABLED    |               |
   |             | Require Role (accessor)     | ● REQUIRED    | ○ ALTERNATIVE | ○ DISABLED    |               |
   | Local Auth  |                             | ○ REQUIRED    | ● ALTERNATIVE | ○ DISABLED    | ○ CONDITIONAL |
   |             | Username Password Form      | ● REQUIRED    |               |               |               |
   |             | Require Role (accessor)     | ● REQUIRED    | ○ ALTERNATIVE | ○ DISABLED    |               |

   where

   * _Require Role (impersonator)_ is configured with

     * alias: impersonator
     * apply to impersonator = true
     * role name = `${clientId}.impersonator`

   * _Require Role (accessor)_ is configured with

     * alias: accessor
     * apply to impersonator = false (default)
     * role name = `${clientId}.accessor`

3. Apply the browser authentication flow to a client.

4. Give users these roles and test!


### identity broker

In this example, Keycloak is an identity broker between identity providers and clients.

TODO ... add Idenity Provider Redirector to the browser flow and implement
_Require Role (accessor)_ in a Post Broker Login flow.


---
Copyright 2023 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
[thomasd]: https://github.com/thomasdarimont
[authext]: https://github.com/thomasdarimont/keycloak-extension-playground/tree/master/auth-require-role-extension
