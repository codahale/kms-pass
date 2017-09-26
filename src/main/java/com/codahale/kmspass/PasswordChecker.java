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

package com.codahale.kmspass;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PasswordChecker {

  private final KMS kms;
  private final String macAlg;
  private final SecureRandom random;

  public PasswordChecker(KMS kms) {
    this(kms, new SecureRandom(), "HmacShs256");
  }

  public PasswordChecker(KMS kms, SecureRandom random, String macAlg) {
    this.kms = kms;
    this.random = random;
    this.macAlg = macAlg;
  }

  public String store(String username, String password)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    // generate a random secret
    final byte[] secret = new byte[16];
    random.nextBytes(secret);

    final byte[] ad = username.getBytes(StandardCharsets.UTF_8);
    final byte[] encSecret = kms.encrypt(secret, ad);

    final Mac mac = Mac.getInstance(macAlg);
    mac.init(new SecretKeySpec(secret, macAlg));
    final byte[] hash = mac.doFinal(password.getBytes(StandardCharsets.UTF_8));

    final byte[] result = new byte[encSecret.length + hash.length];
    System.arraycopy(encSecret, 0, result, 0, encSecret.length);
    System.arraycopy(hash, 0, result, encSecret.length, hash.length);

    return Base64.getEncoder().withoutPadding().encodeToString(result);
  }

  public boolean validate(String username, String stored, String password)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    try {
      final byte[] result = Base64.getDecoder().decode(stored);
      final Mac mac = Mac.getInstance(macAlg);
      final byte[] encSecret = Arrays.copyOfRange(result, 0, result.length - mac.getMacLength());
      final byte[] hash = Arrays
          .copyOfRange(result, result.length - mac.getMacLength(), result.length);

      final byte[] ad = username.getBytes(StandardCharsets.UTF_8);
      final Optional<byte[]> secret = kms.decrypt(encSecret, ad);
      if (!secret.isPresent()) {
        return false;
      }

      mac.init(new SecretKeySpec(secret.get(), macAlg));
      final byte[] candidate = mac.doFinal(password.getBytes(StandardCharsets.UTF_8));
      return MessageDigest.isEqual(hash, candidate);
    } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
      return false;
    }
  }
}
