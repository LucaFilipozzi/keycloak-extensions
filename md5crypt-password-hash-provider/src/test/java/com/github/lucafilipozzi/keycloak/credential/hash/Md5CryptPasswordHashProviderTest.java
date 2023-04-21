// Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE.

package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.Md5Crypt;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runner.RunWith;
import org.keycloak.models.credential.PasswordCredentialModel;

@RequiredArgsConstructor
@RunWith(Parameterized.class)
public class Md5CryptPasswordHashProviderTest {
  private final Md5CryptPasswordHashProvider provider = new Md5CryptPasswordHashProvider();
  private final String password;
  private final String expected;

  @Parameters
  public static List<Object[]> data() {
    return Arrays.asList(new Object[][] {
        /* password, expected */
        { "testingonly$$1234", "$1$PhQy/mw.$dDp.eDLeG6H0gz.WlhNV./" },
        { "Hello$$1234", "$1$v8ZrPcRS$mmBfzNIgRLnYO6jL3mWhr/" },
        { "Wong$$5678", "$1$gr8/T6QQ$Yq/2P3RlGoTHIFmQJ.q1S/" }
    });
  }

  @Test
  public void test() {
    String computed = Md5Crypt.md5Crypt(password.getBytes(), expected);
    PasswordCredentialModel credential = PasswordCredentialModel.createFromValues(PROVIDER_ID, new byte[0], 0, computed);
    assertThat(computed, is(equalTo(expected)));
    assertThat(credential.getPasswordSecretData().getValue(), is(equalTo(expected)));
    assertThat(provider.verify(password, credential), is(equalTo(true)));
  }
}
