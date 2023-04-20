// Copyright (C) 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;

import org.apache.commons.codec.digest.Md5Crypt;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class Md5CryptPasswordHashProvider implements PasswordHashProvider {
  @Override
  public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
    return credential.getPasswordCredentialData().getAlgorithm().equals(PROVIDER_ID);
  }

  @Override
  public PasswordCredentialModel encodedCredential(String rawPassword, int hashIterations) {
    // hashIterations arg is not used because md5Crypt() has fixed (1000) iterations
    // salt is not used because md5Crypt() generates and prepends it to the computed hash
    return PasswordCredentialModel.createFromValues(
        PROVIDER_ID,
        new byte[0],
        0,
        Md5Crypt.md5Crypt(rawPassword.getBytes()));
  }

  @Override
  public String encode(String rawPassword, int hashIterations) {
    // hashIterations arg is not used because md5Crypt has fixed (1000) iterations
    return Md5Crypt.md5Crypt(rawPassword.getBytes());
  }

  @Override
  public boolean verify(String rawPassword, PasswordCredentialModel credential) {
    String expected = credential.getPasswordSecretData().getValue(); // pass as salt to md5Crypt()
    String computed = Md5Crypt.md5Crypt(rawPassword.getBytes(), expected);
    return computed.equals(expected);
  }

  @Override
  public void close() {
    // intentionally empty
  }
}
