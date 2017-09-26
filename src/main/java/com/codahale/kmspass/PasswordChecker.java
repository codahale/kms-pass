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

import com.lambdaworks.crypto.SCrypt;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class PasswordChecker {

  private static final String PREFIX = "kms0";
  private static final int DIGEST_LENGTH = 32;
  private final KMS kms;
  private final byte[] secretKey;
  private final SecureRandom random;
  private final int n, r, p;
  private final String params;

  public PasswordChecker(KMS kms, byte[] secretKey) {
    this(kms, secretKey, new SecureRandom(), 16384, 8, 1);
  }

  public PasswordChecker(KMS kms, byte[] secretKey, SecureRandom random, int n, int r, int p) {
    this.kms = kms;
    this.secretKey = Arrays.copyOf(secretKey, secretKey.length);
    this.random = random;
    this.n = n;
    this.r = r;
    this.p = p;
    this.params = Long.toString(log2(n) << 16L | r << 8 | p, 16);
  }

  public String store(byte[] userData, byte[] password)
      throws IOException, GeneralSecurityException {
    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] ciphertext = kms.encrypt(salt, userData);
    final byte[] key = concat(secretKey, salt);
    final byte[] hash = SCrypt.scrypt(password, key, n, r, p, DIGEST_LENGTH);
    return "$" + PREFIX + "$" + params
        + "$" + Base64.getEncoder().withoutPadding().encodeToString(ciphertext)
        + "$" + Base64.getEncoder().withoutPadding().encodeToString(hash);
  }

  public boolean validate(String stored, byte[] userData, byte[] password)
      throws IOException, GeneralSecurityException {
    final String[] parts = stored.split("\\$");
    if (parts.length != 5 || !parts[1].equals(PREFIX)) {
      return false;
    }

    final long params = Long.parseLong(parts[2], 16);
    final byte[] ciphertext;
    final byte[] hash;
    try {
      ciphertext = Base64.getDecoder().decode(parts[3]);
      hash = Base64.getDecoder().decode(parts[4]);
    } catch (IllegalArgumentException e) {
      return false;
    }

    final int n = (int) Math.pow(2, params >> 16 & 0xffff);
    final int r = (int) params >> 8 & 0xff;
    final int p = (int) params & 0xff;

    final Optional<byte[]> salt = kms.decrypt(ciphertext, userData);
    if (!salt.isPresent()) {
      return false;
    }

    final byte[] key = concat(secretKey, salt.get());
    final byte[] candidate = SCrypt.scrypt(password, key, n, r, p, DIGEST_LENGTH);
    return MessageDigest.isEqual(hash, candidate);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    final byte[] v = new byte[a.length + b.length];
    System.arraycopy(a, 0, v, 0, a.length);
    System.arraycopy(b, 0, v, a.length, b.length);
    return v;
  }

  private static int log2(int n) {
    if (n == 0) {
      return 0;
    }
    return 31 - Integer.numberOfLeadingZeros(n);
  }
}
