# md5crypt-password-hash-provider

## description

This Keycloak extension implements an md5crypt password hash provider which
helps with migrating accounts from a unix system using old hashes into
Keycloak. When users reset their passwords in Keycloak, the default password
hash algorithm will be used used (pbkdf2-sha256) unless altered by an admin.

## user migration

Prepare a JSON file similar to that below containing the users to import into
the the realm. Note that the `algorithm` attribute is set to `md5-crypt`, which
is the PROVIDER_ID specified in Md5CryptPasswordHashProviderFactory. This is
what instructs Keycloak to use Md5CryptPasswordHashProvider to verify the
password entered by a user against the stored md5crypt hash.

```json
[
  {
    "realm": "realm",
    "users": [
      {
        "username": "ab001",
        "enabled": true,
        "firstName": "Alice",
        "lastName": "Doe",
        "email": "alice.doe@example.com",
        "emailVerified": true,
        "credentials": [
          {
            "type": "password",
            "algorithm": "md5-crypt",
            "hashedSaltedValue": "$1$PhQy/mw.$dDp.eDLeG6H0gz.WlhNV./",
            "hashIterations": 0
          }
        ]
      },
      {
        "username": "ab002",
        "enabled": true,
        "firstName": "Bob",
        "lastName": "Doe",
        "email": "bob.doe@example.com",
        "emailVerified": true,
        "credentials": [
          {
            "type": "password",
            "algorithm": "md5-crypt",
            "hashedSaltedValue": "$1$v8ZrPcRS$mmBfzNIgRLnYO6jL3mWhr/",
            "hashIterations": 0
          }
        ]
      },
      {
        "username": "ab003",
        "enabled": true,
        "firstName": "Carol",
        "lastName": "Doe",
        "email": "carol.doe@example.com",
        "emailVerified": true,
        "credentials": [
          {
            "type": "password",
            "algorithm": "md5-crypt",
            "hashedSaltedValue": "$1$gr8/T6QQ$Yq/2P3RlGoTHIFmQJ.q1S/",
            "hashIterations": 0
          }
        ]
      }
    ]
  }
]
```

---
Copyright 2023 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
