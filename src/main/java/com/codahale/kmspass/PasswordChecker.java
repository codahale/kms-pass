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
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordChecker {

  private static final String PREFIX = "kms0";
  private static final int DIGEST_LENGTH = 32;
  private final KMS kms;
  private final byte[] systemKey;
  private final SecureRandom random;
  private final int n, r, p;
  private final String params;

  public PasswordChecker(KMS kms, byte[] systemKey) {
    this(kms, systemKey, new SecureRandom(), 16384, 8, 1);
  }

  public PasswordChecker(KMS kms, byte[] systemKey, SecureRandom random, int n, int r, int p) {
    this.kms = kms;
    this.systemKey = Arrays.copyOf(systemKey, systemKey.length);
    this.random = random;
    this.n = n;
    this.r = r;
    this.p = p;
    this.params = Long.toString(log2(n) << 16L | r << 8 | p, 16);
  }

  private static int log2(int n) {
    if (n == 0) {
      return 0;
    }
    return 31 - Integer.numberOfLeadingZeros(n);
  }

  private static byte[] hmac(byte[] k, byte[] m) {
    try {
      final Mac mac = Mac.getInstance("HmacSha256");
      mac.init(new SecretKeySpec(k, "HmacSha256"));
      return mac.doFinal(m);
    } catch (GeneralSecurityException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static byte[] aes(byte[] k, byte[] m) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), iv);
      return cipher.doFinal(m);
    } catch (GeneralSecurityException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p) {
    try {
      return SCrypt.scrypt(password, salt, n, r, p, DIGEST_LENGTH);
    } catch (GeneralSecurityException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static String base64Encode(byte[] v) {
    return Base64.getEncoder().encodeToString(v);
  }

  private static byte[] base64Decode(String v) {
    try {
      return Base64.getDecoder().decode(v);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  public String store(byte[] userData, byte[] password) throws IOException {
    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] eed = aes(scrypt(password, salt, n, r, p),
        kms.encrypt(hmac(systemKey, password), userData));

    return "$" + PREFIX + "$" + params + "$" + base64Encode(salt) + "$" + base64Encode(eed);
  }

  public boolean validate(String stored, byte[] userData, byte[] password) throws IOException {
    final String[] parts = stored.split("\\$");
    if (parts.length != 5 || !parts[1].equals(PREFIX)) {
      return false;
    }

    final long params = Long.parseLong(parts[2], 16);
    final byte[] salt = base64Decode(parts[3]);
    final byte[] eed = base64Decode(parts[4]);
    if (salt == null || eed == null) {
      return false;
    }

    final int n = (int) Math.pow(2, params >> 16 & 0xffff);
    final int r = (int) params >> 8 & 0xff;
    final int p = (int) params & 0xff;

    final byte[] c = hmac(systemKey, password);
    final byte[] ed = aes(scrypt(password, salt, n, r, p), eed);
    return kms.decrypt(ed, userData).map(v -> MessageDigest.isEqual(v, c)).orElse(false);
  }
}
