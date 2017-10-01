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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
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
  private final String stored = "$kms0$e0801$AAECAwQFBgcICQoLDA0ODw$VYUt";
  private final PasswordChecker checker = new PasswordChecker(kms, secretKey, random, 16384, 8, 1);

  @Test
  void storingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> secret = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    doAnswer(invocation -> {
      final byte[] bytes = invocation.getArgument(0);
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) i;
      }
      return null;
    }).when(random).nextBytes(any());

    when(kms.encrypt(secret.capture(), ad.capture())).thenReturn(new byte[]{1, 2, 3});

    final String hash = checker.store(userData, password);

    assertEquals(stored, hash);
    assertArrayEquals(secret.getValue(),
        new byte[]{-22, 35, 9, 94, -104, 30, 34, -37, -105, 73, 45, -30, 106, 94, 92, 121, 78, -88,
            -8, -76, 0, -47, -94, -120, 3, -61, -111, -103, 57, 97, 52, -59});
    assertArrayEquals(ad.getValue(), userData);
  }

  @Test
  void verifyingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(
        new byte[]{-22, 35, 9, 94, -104, 30, 34, -37, -105, 73, 45, -30, 106, 94, 92, 121, 78, -88,
            -8, -76, 0, -47, -94, -120, 3, -61, -111, -103, 57, 97, 52, -59}));

    final boolean result = checker.validate(stored, userData, password);

    assertTrue(result);
    assertArrayEquals(ciphertext.getValue(), new byte[]{1, 2, 3});
    assertArrayEquals(ad.getValue(), userData);
  }
}