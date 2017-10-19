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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordChecker {

  private static final String PREFIX = "kms0";
  private static final int DIGEST_LENGTH = 32;
  private static final Pattern FORMAT = Pattern.compile("^\\$" + PREFIX +
      "\\$(?<params>[^$]+)\\$(?<salt>[^$]+)\\$(?<authenticator>[^$]+)$");
  private final KMS kms;
  private final SecureRandom random;
  private final int n, r, p;
  private final String params;

  public PasswordChecker(KMS kms) {
    this(kms, new SecureRandom(), 1 << 15, 8, 1);
  }

  public PasswordChecker(KMS kms, SecureRandom random, int n, int r, int p) {
    this.kms = kms;
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

  private static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p) {
    try {
      return SCrypt.scrypt(password, salt, n, r, p, DIGEST_LENGTH);
    } catch (GeneralSecurityException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static String base64Encode(byte[] v) {
    return Base64.getEncoder().withoutPadding().encodeToString(v);
  }

  private static byte[] base64Decode(String v) {
    try {
      return Base64.getDecoder().decode(v);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  public String store(byte[] userData, byte[] password) throws IOException {
    final byte[] salt = new byte[DIGEST_LENGTH];
    random.nextBytes(salt);

    final byte[] verifier = new byte[DIGEST_LENGTH];
    random.nextBytes(verifier);

    final byte[] c = kms.encrypt(verifier, hash(userData, password, salt, n, r, p));
    return "$" + PREFIX + "$" + params + "$" + base64Encode(salt) + "$" + base64Encode(c);
  }

  public boolean validate(String stored, byte[] userData, byte[] password) throws IOException {
    final Matcher matcher = FORMAT.matcher(stored);
    if (!matcher.matches()) {
      return false;
    }

    final long params = Long.parseLong(matcher.group("params"), 16);
    final int n = (int) Math.pow(2, params >> 16 & 0xffff);
    final int r = (int) params >> 8 & 0xff;
    final int p = (int) params & 0xff;

    final byte[] salt = base64Decode(matcher.group("salt"));
    final byte[] c = base64Decode(matcher.group("authenticator"));

    return kms.decrypt(c, hash(userData, password, salt, n, r, p)).isPresent();
  }

  private byte[] hash(byte[] userData, byte[] password, byte[] salt, int n, int r, int p) {
    final byte[] s = new byte[userData.length + salt.length];
    System.arraycopy(salt, 0, s, 0, salt.length);
    System.arraycopy(userData, 0, s, salt.length, userData.length);
    return scrypt(password, s, n, r, p);
  }
}
