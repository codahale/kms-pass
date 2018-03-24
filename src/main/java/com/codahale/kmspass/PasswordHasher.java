/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnegative;

/**
 * {@link PasswordHasher} securely hashes passwords using scrypt and a {@link KMS} implementation.
 *
 * <h2>Storing Passwords</h2>
 *
 * <ol>
 *   <li>Generate two random 256-bit salts.
 *   <li>Generate two scrypt hashes of the password, one for each salt.
 *   <li>Encrypt the second hash via the KMS, using the first hash as authenticated data.
 *   <li>Store the encrypted hash, the two salts, and the scrypt parameters.
 * </ol>
 *
 * <h2>Verifying Passwords</h2>
 *
 * <ol>
 *   <li>Parse the hash into scrypt parameters, salts, and encrypted hash.
 *   <li>Generate two scrypt hashes of the candidate password, one for each salt.
 *   <li>Decrypt the ciphertext via the KMS, using the first hash as authenticated data.
 *   <li>If the KMS returns a plaintext which matches the second hash, the password is valid.
 * </ol>
 *
 * <h2>Implementation Details</h2>
 *
 * <ul>
 *   <li>Passwords are converted into bytes as NFKC-normalized UTF-8.
 *   <li>Hashes are compared using a constant-time algorithm.
 * </ul>
 */
public class PasswordHasher {

  private static final int DIGEST_LENGTH = 32;
  private static final int SALT_LENGTH = 32;
  private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getDecoder();
  private final KMS kms;
  private final SecureRandom random;
  private final int n;
  private final int r;
  private final int p;
  private final String prefix;
  private final Pattern format;

  /**
   * Creates a new {@link PasswordHasher} instance with the given {@link KMS} client using the
   * default {@link SecureRandom} implementation and recommended scrypt parameters.
   *
   * @param kms a {@link KMS} implementation
   * @see <a href="https://blog.filippo.io/the-scrypt-parameters/">The scrypt parameters</a>
   */
  public PasswordHasher(KMS kms) {
    this(kms, new SecureRandom(), 1 << 15, 8, 1);
  }

  /**
   * Creates a new {@link PasswordHasher} instance with the given {@link KMS} client, {@link
   * SecureRandom} implementation, and scrypt parameters.
   *
   * @param kms a {@link KMS} implementation
   * @param random a {@link SecureRandom} instance
   * @param n scrypt iteration count
   * @param r scrypt block size
   * @param p scrypt parallelism parameter
   */
  public PasswordHasher(
      KMS kms, SecureRandom random, @Nonnegative int n, @Nonnegative int r, @Nonnegative int p) {
    this.kms = kms;
    this.random = random;
    this.n = n;
    this.r = r;
    this.p = p;
    this.prefix = "$" + kms.getName() + "$" + Long.toString(log2(n) << 16L | r << 8 | p, 16) + "$";
    this.format =
        Pattern.compile(
            "^\\$"
                + Pattern.quote(kms.getName())
                + "\\$(?<params>[^$]+)\\$(?<saltA>[^$]+)\\$(?<saltB>[^$]+)\\$(?<ciphertext>[^$]+)$");
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

  private static byte[] normalize(String password) {
    return Normalizer.normalize(password, Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Securely hashes the given password.
   *
   * @param password a user's password
   * @return a secure hash of {@code password}
   * @throws IOException if there is an error communicating with the KMS
   */
  @CheckReturnValue
  public String hash(String password) throws IOException {
    final byte[] b = normalize(password);
    final byte[] saltA = newSalt();
    final byte[] saltB = newSalt();
    final byte[] hashA = scrypt(b, saltA, n, r, p);
    final byte[] hashB = scrypt(b, saltB, n, r, p);
    final byte[] c = kms.encrypt(hashB, hashA);
    return prefix
        + ENCODER.encodeToString(saltA)
        + "$"
        + ENCODER.encodeToString(saltB)
        + "$"
        + ENCODER.encodeToString(c);
  }

  /**
   * Securely compares a stored hash with a candidate password.
   *
   * @param hash the result of {@link #hash(String)}
   * @param password a candidate password
   * @return true if {@code password} is the same as the hashed password
   * @throws IOException if there is an error communicating with the KMS
   */
  @CheckReturnValue
  public boolean validate(String hash, String password) throws IOException {
    final byte[] b = normalize(password);
    final Matcher matcher = format.matcher(hash);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Invalid hash");
    }

    final long params = Long.parseLong(matcher.group("params"), 16);
    final int hashN = (int) Math.pow(2, params >> 16 & 0xffff);
    final int hashR = (int) params >> 8 & 0xff;
    final int hashP = (int) params & 0xff;

    final byte[] saltA = DECODER.decode(matcher.group("saltA"));
    final byte[] saltB = DECODER.decode(matcher.group("saltB"));
    final byte[] hashA = scrypt(b, saltA, hashN, hashR, hashP);
    final byte[] hashB = scrypt(b, saltB, hashN, hashR, hashP);
    final byte[] ciphertext = DECODER.decode(matcher.group("ciphertext"));
    return kms.decrypt(ciphertext, hashA).map(v -> MessageDigest.isEqual(v, hashB)).orElse(false);
  }

  private byte[] newSalt() {
    final byte[] salt = new byte[SALT_LENGTH];
    random.nextBytes(salt);
    return salt;
  }
}
