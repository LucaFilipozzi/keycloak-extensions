# cache-required-actions-authenticator

## description

This authenticator is used to cache and restore required actions. When using
direct grants, it is not possible for the user to process any required actions
(such as UPDATE_PASSWORD) so the attempt at obtaining a token via direct grant
will fail.

By adding this authenticator in a pair-wise way (to the _Direct Grant_ flow and
also to the _Browser_ flow), it is possible to cache (in the Direct Grant flow)
any required actions so that the attempt at obtaining a token via direct grant
succeeds and to restore (in the Browser flow) the cached required actions.

## usage

Add this authenticator to
* _Direct Grant_ flow with _restore_ set to false (default)
* _Browser_ flow, with _restore_ set to true

---
Copyright 2023 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
