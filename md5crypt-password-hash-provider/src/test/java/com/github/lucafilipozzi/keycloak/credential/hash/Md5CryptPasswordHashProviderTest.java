package com.github.lucafilipozzi.keycloak.credential.hash;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import java.util.Arrays;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runner.RunWith;

@RunWith(Parameterized.class)
public class Md5CryptPasswordHashProviderTest {
  private Md5CryptPasswordHashProvider provider;
  private final String rawPassword;
  private final String expected;

  public Md5CryptPasswordHashProviderTest(String rawPassword, String expected) {
    this.rawPassword = rawPassword;
    this.expected = expected;
  }

  @Before
  public void setUp() {
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
  public void testGenerateEncodedPassword() {
    String salt = expected.substring(0, 11);
    String computed = provider.generateEncodedPassword(rawPassword, salt);
    assertThat(computed, is(equalTo(expected)));
  }
}
