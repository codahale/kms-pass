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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codahale.kmspass.KMS;
import com.codahale.kmspass.PasswordChecker;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class PasswordCheckerTest {

  private final KMS kms = mock(KMS.class);
  private final SecureRandom random = mock(SecureRandom.class);
  private final byte[] secretKey = "this is secret too".getBytes(StandardCharsets.UTF_8);
  private final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
  private final byte[] userData = "username".getBytes(StandardCharsets.UTF_8);
  private final PasswordChecker checker = new PasswordChecker(kms, secretKey, random, "HmacSha1");

  @Test
  void storingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> secret = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.encrypt(secret.capture(), ad.capture())).thenReturn(new byte[]{1, 2, 3});

    final String hash = checker.store(userData, password);

    assertEquals("AQIDJ2VBNWCk3aL/LRFIO8h3g5T3TgM", hash);
    assertArrayEquals(secret.getValue(), new byte[16]);
    assertArrayEquals(ad.getValue(), userData);
  }

  @Test
  void verifyingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(new byte[16]));

    final boolean result = checker.validate("AQIDJ2VBNWCk3aL/LRFIO8h3g5T3TgM", userData, password);

    assertTrue(result);
    assertArrayEquals(ciphertext.getValue(), new byte[]{1, 2, 3});
    assertArrayEquals(ad.getValue(), "username".getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void wrongPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(new byte[16]));

    final boolean result = checker
        .validate("AQIDrgqoFHiJ6Aw9nYFzFVrPDHdIcrE", userData, new byte[]{1, 2, 3});

    assertFalse(result);
    assertArrayEquals(ciphertext.getValue(), new byte[]{1, 2, 3});
    assertArrayEquals(ad.getValue(), userData);
  }

  @Test
  void wrongUser() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.empty());

    final boolean result = checker
        .validate("AQIDrgqoFHiJ6Aw9nYFzFVrPDHdIcrE", new byte[]{4, 5, 6}, password);

    assertFalse(result);
    assertArrayEquals(ciphertext.getValue(), new byte[]{1, 2, 3});
    assertArrayEquals(ad.getValue(), new byte[]{4, 5, 6});
  }

  @Test
  void badStoredPassword() throws Exception {
    assertFalse(checker.validate("%%%AQIDrgqoFHiJ6Aw9nYFzFVrPDHdIcrE", userData, password));
  }

  @Test
  void shortStoredPassword() throws Exception {
    assertFalse(checker.validate("AQIDrgqoFHiJ6Aw9nYFzFVrPDHd", userData, password));
  }
}