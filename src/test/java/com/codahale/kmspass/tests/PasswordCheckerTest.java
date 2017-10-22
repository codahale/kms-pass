/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.kmspass.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codahale.kmspass.KMS;
import com.codahale.kmspass.PasswordChecker;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

class PasswordCheckerTest {

  private final KMS kms = mock(KMS.class);
  private final SecureRandom random = mock(SecureRandom.class);
  private final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
  private final byte[] kmsCiphertext = {1, 2, 3};
  private final byte[] hashA = {108, 108, -44, -101, -95, 62, 84, -2, -127, -9, -88, -121, 105, 92,
      -116, -59, 51, -97, 73, 58, -39, 96, 44, 52, 9, -117, 48, 39, 12, -72, 120, -70};
  private final byte[] hashB = {66, -6, 54, 98, 25, -54, 107, -119, -105, 5, -103, 7, -92, -21, 65,
      108, -8, -39, 17, 116, -107, 114, -33, -68, -47, 103, 8, 75, 88, 7, -11, 36};
  private final String stored = "$kms0$e0801$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8$AQID";
  private final PasswordChecker checker = new PasswordChecker(kms, random, 16384, 8, 1);

  @Test
  void storingAPassword() throws Exception {

    final Answer<?> rng = new Answer<Object>() {
      private int v = 0;

      @Override
      public Object answer(InvocationOnMock invocation) throws Throwable {
        final byte[] bytes = invocation.getArgument(0);
        for (int i = 0; i < bytes.length; i++) {
          bytes[i] = (byte) v++;
        }
        return null;
      }
    };

    doAnswer(rng).when(random).nextBytes(any());

    final ArgumentCaptor<byte[]> plaintext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);
    when(kms.encrypt(plaintext.capture(), ad.capture())).thenReturn(kmsCiphertext);

    assertEquals(stored, checker.store(password));
    assertArrayEquals(plaintext.getValue(), hashA);
    assertArrayEquals(ad.getValue(), hashB);
  }

  @Test
  void verifyingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(hashA));

    assertTrue(checker.validate(stored, password));
    assertArrayEquals(ciphertext.getValue(), kmsCiphertext);
    assertArrayEquals(ad.getValue(), hashB);
  }

  @Test
  void verifyingABadPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.empty());

    assertFalse(checker.validate(stored, "woop".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(ciphertext.getValue(), kmsCiphertext);
  }

  @Test
  void verifyingAnUnparsableHash() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> checker.validate("bloop", password));
    verify(kms, never()).decrypt(any(), any());
  }

  @Test
  void verifyingPasswordWithCompromisedKMS() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(new byte[]{3, 4}));

    assertFalse(checker.validate(stored, "woop".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(ciphertext.getValue(), kmsCiphertext);
  }
}