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

import com.google.api.gax.rpc.ApiException;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import java.util.Optional;

/** A {@link KMS} implementation backed by Google Cloud Platform's Key Management Service. */
public class GoogleKMS implements KMS {

  private final KeyManagementServiceClient kms;
  private final String keyId;

  /**
   * Create a new {@link GoogleKMS}.
   *
   * @param kms a GCP KMS client
   * @param keyId the ID of the KMS key to use for operations
   */
  public GoogleKMS(KeyManagementServiceClient kms, String keyId) {
    this.kms = kms;
    this.keyId = keyId;
  }

  @Override
  public String getName() {
    return "gcp-kms";
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] ad) {
    return kms.encrypt(
            EncryptRequest.newBuilder()
                .setName(keyId)
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setAdditionalAuthenticatedData(ByteString.copyFrom(ad))
                .build())
        .getCiphertext()
        .toByteArray();
  }

  @Override
  public Optional<byte[]> decrypt(byte[] ciphertext, byte[] ad) {
    try {
      return Optional.of(
          kms.decrypt(
                  DecryptRequest.newBuilder()
                      .setName(keyId)
                      .setCiphertext(ByteString.copyFrom(ciphertext))
                      .setAdditionalAuthenticatedData(ByteString.copyFrom(ad))
                      .build())
              .getPlaintext()
              .toByteArray());
    } catch (ApiException e) {
      if (e.getStatusCode().getCode().getHttpStatusCode() == 400) {
        return Optional.empty();
      }
      throw e;
    }
  }
}
