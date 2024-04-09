# login-event-listener-provider

## description

This event listener provider performs two functions:
- updates `last-login` attribute
- emits a `LOGIN` log entry at `WARN` level

## usage

1. copy the JAR to the deployment directory
2. add a `last-login` attribute to the realm's declarative user profile with
   - permissions
     - user can view set false
     - admin can view set true
     - user can edit set false
     - admin can edit set false
   - validations
     - pattern validator
       - pattern:`^[0-9]+$`
       - message: `invalid timestamp (in milliseconds)`
3. add `login-event-listener` to the realm's event listeners

---

© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
