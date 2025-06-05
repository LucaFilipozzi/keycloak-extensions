# update-password-event-listener-provider

## description

This event listener provider listens for the **UPDATE_PASSWORD** event and
syncs the updated password from the *source user* (for whom the event was
emitted) to zero or more *target users* specified in the ***password sync***
attribute of the *source user*.*

## usage

1. copy the JAR to the deployment directory
2. add the listener to list of event listeners
3. define a `password-sync` attribute if the declarative user profile
   feature has been enabled
4. to the user whose password should be synced to other users, add the
   `password-sync` attribute containing the username(s) of the other users,
   delimited by `##`; for example, if alice's password should be synced to
   - to bob: set alice's `password-sync` to `bob`
   - to bob and carol: set alice's `password-sync` to `bob##alice`

---

© 2025 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md

