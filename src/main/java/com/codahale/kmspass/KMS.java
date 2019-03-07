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

import java.io.IOException;
import java.util.Optional;

/** A interface for generic key management services like AWS KMS, Google Cloud KMS, Vault, etc. */
public interface KMS {

  /**
   * The name of the KMS, used when storing passwords.
   *
   * @return the name of the KMS
   */
  String name();

  /**
   * Encrypt the given plaintext, using the given authenticated data, and return the ciphertext.
   *
   * @param plaintext an arbitrary plaintext
   * @param authenticatedData an arbitrary bytestring
   * @return {@code plaintext}, encrypted
   * @throws IOException if there is an error communicating with the KMS
   */
  byte[] encrypt(byte[] plaintext, byte[] authenticatedData) throws IOException;

  /**
   * Decrypt the given ciphertext, using the given authenticated data, and return the plaintext.
   *
   * @param ciphertext a KMS-encrypted message
   * @param authenticatedData the authenticated data used to create {@code ciphertext}
   * @return if the ciphertext can be decrypted, the plaintext; otherwise, an empty {@link Optional}
   * @throws IOException if there is an error communicating with the KMS
   */
  Optional<byte[]> decrypt(byte[] ciphertext, byte[] authenticatedData) throws IOException;
}
