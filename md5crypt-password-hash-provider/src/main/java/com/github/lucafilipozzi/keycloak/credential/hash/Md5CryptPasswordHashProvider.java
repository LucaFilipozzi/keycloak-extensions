// Copyright (C) 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;

import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.lang.RandomStringUtils;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class Md5CryptPasswordHashProvider implements PasswordHashProvider {
  @Override
  public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
    return credential.getPasswordCredentialData().getAlgorithm().equals(PROVIDER_ID);
  }

  @Override
  public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
    final byte[] salt = new byte[0]; // unused: encodedPassword contains the salt: $1$«salt»$«hash»
    final int hashIterations = 0;    // unused: since Md5Crypt has fixed number of iterations
    return PasswordCredentialModel.createFromValues(
        PROVIDER_ID,
        salt,
        hashIterations,
        generateEncodedPassword(rawPassword, generateRandomSalt())
    );
  }

  @Override
  public String encode(String rawPassword, int hashIterations) {
    return generateEncodedPassword(rawPassword, generateRandomSalt());
  }

  @Override
  public boolean verify(String rawPassword, PasswordCredentialModel credential) {
    String encodedPassword = credential.getPasswordSecretData().getValue();
    String salt = encodedPassword.substring(0, 11); // salt is embedded in encodedPassword
    return encodedPassword.equals(generateEncodedPassword(rawPassword, salt));
  }

  @Override
  public void close() {
    // intentionally empty
  }

  String generateRandomSalt() {
    return "$1$" + RandomStringUtils.randomAlphanumeric(8);
  }

  String generateEncodedPassword(String password, String salt) {
    return Crypt.crypt(password, salt); // salt must have $1$ prefix
  }
}
