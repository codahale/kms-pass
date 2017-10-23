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

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import java.io.IOException;
import java.util.Optional;

public class GoogleKMS implements KMS {

  private final CloudKMS kms;
  private final String keyId;

  public GoogleKMS(CloudKMS kms, String keyId) {
    this.kms = kms;
    this.keyId = keyId;
  }

  @Override
  public String getName() {
    return "gcp-kms";
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] ad) throws IOException {
    final EncryptRequest request = new EncryptRequest().encodePlaintext(plaintext)
                                                       .encodeAdditionalAuthenticatedData(ad);
    final EncryptResponse response = kms.projects().locations().keyRings().cryptoKeys()
                                        .encrypt(keyId, request).execute();
    return response.decodeCiphertext();
  }

  @Override
  public Optional<byte[]> decrypt(byte[] ciphertext, byte[] ad) throws IOException {
    try {
      final DecryptRequest request = new DecryptRequest().encodeCiphertext(ciphertext)
                                                         .encodeAdditionalAuthenticatedData(ad);
      final DecryptResponse response = kms.projects().locations().keyRings().cryptoKeys()
                                          .decrypt(keyId, request).execute();
      return Optional.of(response.decodePlaintext());
    } catch (GoogleJsonResponseException e) {
      if (e.getDetails().getCode() == 400) {
        return Optional.empty();
      }
      throw e;
    }
  }
}
