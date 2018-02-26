/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.codahale.kmspass.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codahale.kmspass.KMS;
import com.codahale.kmspass.PasswordHasher;
import java.security.SecureRandom;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class PasswordHasherTest {

  private final KMS kms = mock(KMS.class);
  private final SecureRandom random = mock(SecureRandom.class);
  private final String password = "password";
  private final byte[] kmsCiphertext = {1, 2, 3};
  private final byte[] hashA = {
    108, 108, -44, -101, -95, 62, 84, -2, -127, -9, -88, -121, 105, 92, -116, -59, 51, -97, 73, 58,
    -39, 96, 44, 52, 9, -117, 48, 39, 12, -72, 120, -70
  };
  private final byte[] hashB = {
    66, -6, 54, 98, 25, -54, 107, -119, -105, 5, -103, 7, -92, -21, 65, 108, -8, -39, 17, 116, -107,
    114, -33, -68, -47, 103, 8, 75, 88, 7, -11, 36
  };
  private final String stored =
      "$kms0$e0801$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8$AQID";

  @SuppressWarnings("NullAway")
  private PasswordHasher hasher;

  @Before
  public void setUp() {
    when(kms.getName()).thenReturn("kms0");
    this.hasher = new PasswordHasher(kms, random, 16384, 8, 1);
  }

  @Test
  public void storingAPassword() throws Exception {

    final Answer<?> rng =
        new Answer<Object>() {
          private int v = 0;

          @Override
          public Object answer(InvocationOnMock invocation) {
            final byte[] bytes = invocation.getArgument(0);
            for (int i = 0; i < bytes.length; i++) {
              bytes[i] = (byte) v++;
            }
            return "ok";
          }
        };

    doAnswer(rng).when(random).nextBytes(any());

    final ArgumentCaptor<byte[]> plaintext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);
    when(kms.encrypt(plaintext.capture(), ad.capture())).thenReturn(kmsCiphertext);

    assertThat(hasher.hash(password)).isEqualTo(stored);
    assertThat(plaintext.getValue()).isEqualTo(hashA);
    assertThat(ad.getValue()).isEqualTo(hashB);
  }

  @Test
  public void verifyingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(hashA));

    assertThat(hasher.validate(stored, password)).isTrue();
    assertThat(ciphertext.getValue()).isEqualTo(kmsCiphertext);
    assertThat(ad.getValue()).isEqualTo(hashB);
  }

  @Test
  public void verifyingABadPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.empty());

    assertThat(hasher.validate(stored, "woop")).isFalse();
    assertThat(ciphertext.getValue()).isEqualTo(kmsCiphertext);
  }

  @SuppressWarnings("ResultOfMethodCallIgnored")
  @Test
  public void verifyingAnUnparsableHash() throws Exception {
    assertThatThrownBy(() -> hasher.validate("bloop", password))
        .isInstanceOf(IllegalArgumentException.class);
    verify(kms, never()).decrypt(any(), any());
  }

  @Test
  public void verifyingPasswordWithCompromisedKMS() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture()))
        .thenReturn(Optional.of(new byte[] {3, 4}));

    assertThat(hasher.validate(stored, "woop")).isFalse();
    assertThat(ciphertext.getValue()).isEqualTo(kmsCiphertext);
  }
}
