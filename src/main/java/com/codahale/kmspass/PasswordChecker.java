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
  private final byte[] secretKey;
  private final String macAlg;
  private final SecureRandom random;

  public PasswordChecker(KMS kms, byte[] secretKey) {
    this(kms, secretKey, new SecureRandom(), "HmacShs256");
  }

  public PasswordChecker(KMS kms, byte[] secretKey, SecureRandom random, String macAlg) {
    this.kms = kms;
    this.secretKey = Arrays.copyOf(secretKey, secretKey.length);
    this.random = random;
    this.macAlg = macAlg;
  }

  public String store(byte[] userData, byte[] password)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    // generate a random salt
    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] ciphertext = kms.encrypt(salt, userData);

    final byte[] key = new byte[salt.length + secretKey.length];
    System.arraycopy(secretKey, 0, key, 0, secretKey.length);
    System.arraycopy(salt, 0, key, secretKey.length, salt.length);

    final Mac mac = Mac.getInstance(macAlg);
    mac.init(new SecretKeySpec(key, macAlg));
    final byte[] hash = mac.doFinal(password);

    final byte[] result = new byte[ciphertext.length + hash.length];
    System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
    System.arraycopy(hash, 0, result, ciphertext.length, hash.length);

    return Base64.getEncoder().withoutPadding().encodeToString(result);
  }

  public boolean validate(String stored, byte[] userData, byte[] password)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    try {
      final byte[] result = Base64.getDecoder().decode(stored);
      final Mac mac = Mac.getInstance(macAlg);
      final byte[] ciphertext = Arrays.copyOfRange(result, 0, result.length - mac.getMacLength());
      final byte[] hash = Arrays
          .copyOfRange(result, result.length - mac.getMacLength(), result.length);

      final Optional<byte[]> salt = kms.decrypt(ciphertext, userData);
      if (!salt.isPresent()) {
        return false;
      }

      final byte[] key = new byte[salt.get().length + secretKey.length];
      System.arraycopy(secretKey, 0, key, 0, secretKey.length);
      System.arraycopy(salt.get(), 0, key, secretKey.length, salt.get().length);

      mac.init(new SecretKeySpec(key, macAlg));
      final byte[] candidate = mac.doFinal(password);
      return MessageDigest.isEqual(hash, candidate);
    } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
      return false;
    }
  }
}
