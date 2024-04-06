# extended-cookie-authenticator

## description

This _Browser_ authenticator extends the delivered _Cookie_ authenticator by
overriding the `authenticate` method such that, if the user session notes
contain `IMPERSONATOR_ID`, then the impersonator is validated to have been
assigned at least one client role that is composited, however deeply, from
__realm-management.impersonation__.

If so, then the list of such assigned client roles is added as a
`IMPERSONATOR_ROLES` user session note (for later use with the client _User
Session Note Mapper_) and impersonation is granted.

If not, then impersonation is denied.

## usage

* create a copy of the delivered browser flow and replace _Cookie_ with _Extended Cookie_
* configure the client to use that flow rather than the delivered flow
* create client role(s) that are directly or indirectly, however deeply, composited
  with __realm-management.impersonation__; for example:
  * direct: client role __impersonator__ composited with
    * __realm-management.impersonation__
    * __realm-management.view-users__
  * indirect: client role __impersonator__ composited with
    * realm role __impersonator__ composited with
      * __realm-management.impersonation__
      * __realm-management.view-users__
* assign the client role(s) to users who should be granted the ability to impersonate a
  user into the client

---
© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
