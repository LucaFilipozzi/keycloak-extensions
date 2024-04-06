# force-reauthentication-authenticator

## description

This authenticator, when added to the cookie section of browser flow, forces
reauthentication regardless of whether the OIDC (prompt=login) or the SAML
(ForceAuthN=true) client requested it, placing the decision with the IdP
operator rather than the SP operator.

## usage

This authenticator is not ready for use.

---
© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
