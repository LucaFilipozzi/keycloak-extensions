package com.github.lucafilipozzi.keycloak.credential.hash;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import org.junit.Test;

public class Md5CryptPasswordHashProviderTest {
  @Test
  public void test1() {
    Md5CryptPasswordHashProvider provider = new Md5CryptPasswordHashProvider();
    String pass = "testingonly$$1234";
    String salt = "PhQy/mw.";
    String hash = "dDp.eDLeG6H0gz.WlhNV./";
    assertThat(provider.generateHash(pass, salt.getBytes()), is(equalTo(hash)));
  }

  @Test
  public void test2() {
    Md5CryptPasswordHashProvider provider = new Md5CryptPasswordHashProvider();
    String pass = "Hello$$1234";
    String salt = "v8ZrPcRS";
    String hash = "mmBfzNIgRLnYO6jL3mWhr/";
    assertThat(provider.generateHash(pass, salt.getBytes()), is(equalTo(hash)));
  }

  @Test
  public void test3() {
    Md5CryptPasswordHashProvider provider = new Md5CryptPasswordHashProvider();
    String pass = "Wong$$5678";
    String salt = "gr8/T6QQ";
    String hash = "Yq/2P3RlGoTHIFmQJ.q1S/";
    assertThat(provider.generateHash(pass, salt.getBytes()), is(equalTo(hash)));
  }
}