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

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.InvalidCiphertextException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Optional;

/** A {@link KMS} implementation backed by Amazon Web Service's Key Management Service. */
public class AmazonKMS implements KMS {

  private final AWSKMS kms;
  private final String keyId;

  /**
   * Create a new {@link AmazonKMS}.
   *
   * @param kms an Amazon KMS client
   * @param keyId the ID of the KMS key to use for operations
   */
  public AmazonKMS(AWSKMS kms, String keyId) {
    this.kms = kms;
    this.keyId = keyId;
  }

  @Override
  public String getName() {
    return "aws-kms";
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] authenticatedData) {
    final EncryptRequest req =
        new EncryptRequest()
            .withKeyId(keyId)
            .withPlaintext(ByteBuffer.wrap(plaintext))
            .addEncryptionContextEntry("ad", Base64.getEncoder().encodeToString(authenticatedData));
    final EncryptResult res = kms.encrypt(req);
    return res.getCiphertextBlob().array();
  }

  @Override
  public Optional<byte[]> decrypt(byte[] ciphertext, byte[] authenticatedData) {
    final DecryptRequest req =
        new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(ciphertext))
            .addEncryptionContextEntry("ad", Base64.getEncoder().encodeToString(authenticatedData));
    try {
      return Optional.of(kms.decrypt(req).getPlaintext().array());
    } catch (InvalidCiphertextException e) {
      return Optional.empty();
    }
  }
}
