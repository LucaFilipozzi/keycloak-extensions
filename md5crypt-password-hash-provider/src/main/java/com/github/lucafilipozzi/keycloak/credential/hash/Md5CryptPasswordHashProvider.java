// Copyright (C) 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;

import java.security.SecureRandom;
import org.apache.commons.codec.digest.Crypt;
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
    // iterations is unused because Md5Crypt has a fixed number of iterations (1000)
    byte[] salt = generateSalt();
    String hash = generateHash(password, salt);
    return PasswordCredentialModel.createFromValues(PROVIDER_ID, salt, iterations, hash);
  }

  @Override
  public String encode(String password, int iterations) { // XXX is this ever used?
    // iterations is unused because Md5Crypt has a fixed number of iterations (1000)
    return generateHash(password, generateSalt());
  }

  @Override
  public boolean verify(String password, PasswordCredentialModel credential) {
    return credential.getPasswordSecretData().getValue().equals(
        generateHash(password, credential.getPasswordSecretData().getSalt()));
  }

  @Override
  public void close() {
    // intentionally empty
  }

  byte[] generateSalt() {
    byte[] buffer = new byte[8];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(buffer);
    return buffer;
  }

  String generateHash(String password, byte[] salt) {
    return Crypt.crypt(password, String.format("$1$%s", new String(salt))).split("\\$")[3];
  }
}
