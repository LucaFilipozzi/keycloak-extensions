package com.github.lucafilipozzi.keycloak.credential.hash;

import static com.github.lucafilipozzi.keycloak.credential.hash.Md5CryptPasswordHashProviderFactory.PROVIDER_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.codec.digest.Md5Crypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runner.RunWith;
import org.keycloak.models.credential.PasswordCredentialModel;

@RunWith(Parameterized.class)
public class Md5CryptPasswordHashProviderTest {
  private Md5CryptPasswordHashProvider provider;
  private final String password;
  private final String expected;

  public Md5CryptPasswordHashProviderTest(String password, String expected) {
    this.password = password;
    this.expected = expected;
  }

  @Before
  public void init() {
    provider = new Md5CryptPasswordHashProvider();
  }

  @Parameters
  public static List<Object[]> data() {
    return Arrays.asList(new Object[][] {
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
