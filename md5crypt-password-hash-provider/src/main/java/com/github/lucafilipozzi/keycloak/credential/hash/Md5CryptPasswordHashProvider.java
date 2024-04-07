// © 2024 Luca Filipozzi. Some rights reserved. See LICENSE.
package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;

import java.nio.charset.StandardCharsets;
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
  public PasswordCredentialModel encodedCredential(String password, int iterations) {
    return PasswordCredentialModel.createFromValues(
        PROVIDER_ID, new byte[0], 0, md5Crypt(password));
  }

  @Override
  public String encode(String password, int iterations) {
    return md5Crypt(password);
  }

  @Override
  public boolean verify(String password, PasswordCredentialModel credential) {
    String hash = credential.getPasswordSecretData().getValue();
    return md5Crypt(password, hash).equals(hash);
  }

  @Override
  public void close() {
    // intentionally empty
  }

  private String md5Crypt(String password) {
    return Md5Crypt.md5Crypt(password.getBytes(StandardCharsets.UTF_8));
  }

  private String md5Crypt(String password, String salt) {
    return Md5Crypt.md5Crypt(password.getBytes(StandardCharsets.UTF_8), salt);
  }
}
