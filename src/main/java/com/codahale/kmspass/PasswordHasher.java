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
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnegative;

public class PasswordHasher {

  private static final int DIGEST_LENGTH = 32;
  private static final int SALT_LENGTH = 32;
  private final KMS kms;
  private final SecureRandom random;
  private final int n, r, p;
  private final String prefix;
  private final Pattern format;

  public PasswordHasher(KMS kms) {
    this(kms, new SecureRandom(), 1 << 15, 8, 1);
  }

  public PasswordHasher(KMS kms, SecureRandom random, @Nonnegative int n, @Nonnegative int r,
      @Nonnegative int p) {
    this.kms = kms;
    this.random = random;
    this.n = n;
    this.r = r;
    this.p = p;
    this.prefix = "$" + kms.getName() + "$" + Long.toString(log2(n) << 16L | r << 8 | p, 16) + "$";
    this.format = Pattern.compile("^\\$" + Pattern.quote(kms.getName()) +
        "\\$(?<params>[^$]+)\\$(?<saltA>[^$]+)\\$(?<saltB>[^$]+)\\$(?<ciphertext>[^$]+)$");
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

  @CheckReturnValue
  public String hash(byte[] password) throws IOException {
    final byte[] saltA = newSalt();
    final byte[] saltB = newSalt();
    final byte[] hashA = scrypt(password, saltA, n, r, p);
    final byte[] hashB = scrypt(password, saltB, n, r, p);
    final byte[] c = kms.encrypt(hashB, hashA);
    return prefix + base64Encode(saltA) + "$" + base64Encode(saltB) + "$" + base64Encode(c);
  }

  @CheckReturnValue
  public boolean validate(String hash, byte[] password) throws IOException {
    final Matcher matcher = format.matcher(hash);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Invalid hash");
    }

    final long params = Long.parseLong(matcher.group("params"), 16);
    final int n = (int) Math.pow(2, params >> 16 & 0xffff);
    final int r = (int) params >> 8 & 0xff;
    final int p = (int) params & 0xff;

    final byte[] saltA = base64Decode(matcher.group("saltA"));
    final byte[] saltB = base64Decode(matcher.group("saltB"));
    final byte[] hashA = scrypt(password, saltA, n, r, p);
    final byte[] hashB = scrypt(password, saltB, n, r, p);
    final byte[] ciphertext = base64Decode(matcher.group("ciphertext"));
    return kms.decrypt(ciphertext, hashA).map(v -> MessageDigest.isEqual(v, hashB)).orElse(false);
  }

  private byte[] newSalt() {
    final byte[] salt = new byte[SALT_LENGTH];
    random.nextBytes(salt);
    return salt;
  }
}