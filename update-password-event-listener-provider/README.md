# update-password-event-listener-provider

## description

This event listener provider listens for the **UPDATE_CREDENTIAL** event and
syncs the updated password from the *source user* (for whom the event was
emitted) to zero or more *target users* specified in the ***password sync***
attribute of the *source user*.

## usage

1. copy the JAR to the providers directory and rebuild the optimized jar
2. add the listener to realm's active event listeners
3. define a `password-sync` multi-valued attribute
4. to the user whose password should be synced to other users, add the
   username(s) to the `password-sync` attribute

---

© 2025 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md

