# username-policy-authenticator

## description

This _First Login_ authenticator ensures that the username provided by
an identity provider (possibly mapped) conforms to the configured
pattern (regular expression).

## usage

1. copy the JAR to the deployment directory
2. add this authenticator to a _First Login_ flow and define the regex
3. use a identity provider username mapper to define which claim /
   assertion should be considered the username

---

© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md

