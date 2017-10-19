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
  private final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
  private final byte[] userData = "username".getBytes(StandardCharsets.UTF_8);
  private final byte[] kmsCiphertext = {1, 2, 3};
  private final byte[] passwordHash = {49, 70, -18, -14, 120, 82, 76, -20, 36, -68, 114, -119, 15,
      -72, -32, 47, 104, 3, -83, -63, 52, -64, 17, 2, -85, 104, -125, -43, -107, -75, -74, -62};
  private final String stored = "$kms0$e0801$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$AQID";
  private final PasswordChecker checker = new PasswordChecker(kms, random, 16384, 8, 1);

  @Test
  void storingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    doAnswer(invocation -> {
      final byte[] bytes = invocation.getArgument(0);
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) i;
      }
      return null;
    }).when(random).nextBytes(any());

    when(kms.encrypt(any(), ad.capture())).thenReturn(kmsCiphertext);

    assertEquals(stored, checker.store(userData, password));
    assertArrayEquals(ad.getValue(), passwordHash);
  }

  @Test
  void verifyingAPassword() throws Exception {
    final ArgumentCaptor<byte[]> ciphertext = ArgumentCaptor.forClass(byte[].class);
    final ArgumentCaptor<byte[]> ad = ArgumentCaptor.forClass(byte[].class);

    when(kms.decrypt(ciphertext.capture(), ad.capture())).thenReturn(Optional.of(passwordHash));

    assertTrue(checker.validate(stored, userData, password));
    assertArrayEquals(ciphertext.getValue(), kmsCiphertext);
    assertArrayEquals(ad.getValue(), passwordHash);
  }
}